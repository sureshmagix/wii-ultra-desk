//! Native-owned desktop protocol and macOS capture/input adapter.
//!
//! This is deliberately a small, explicit protocol rather than a general RPC
//! channel. The host alone captures pixels and applies input after its own
//! scoped authorization check. Other targets fail with an explicit capability
//! error until their runtime adapters have been exercised on hardware.

use std::collections::HashSet;

use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
use serde::{Deserialize, Serialize};

use crate::{AgentError, Result};

pub const DESKTOP_PROTOCOL_VERSION: u8 = 1;
pub const MAX_DESKTOP_MESSAGE_BYTES: usize = 80 * 1024;
pub const MAX_DESKTOP_JPEG_BYTES: usize = 52 * 1024;
pub const MAX_INPUT_TEXT_BYTES: usize = 256;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QualityMode {
    Auto,
    ClearText,
    SmoothMotion,
    LowBandwidth,
}

#[derive(Clone, Copy, Debug)]
pub struct QualityProfile {
    pub maximum_width: u32,
    pub maximum_height: u32,
    pub jpeg_quality: u8,
    pub frames_per_second: u8,
}

impl QualityMode {
    pub fn profile(self) -> QualityProfile {
        match self {
            // Auto begins conservatively and is adjusted by QualityController.
            Self::Auto => QualityProfile {
                maximum_width: 640,
                maximum_height: 360,
                jpeg_quality: 52,
                frames_per_second: 6,
            },
            Self::ClearText => QualityProfile {
                maximum_width: 960,
                maximum_height: 540,
                jpeg_quality: 76,
                frames_per_second: 4,
            },
            Self::SmoothMotion => QualityProfile {
                maximum_width: 640,
                maximum_height: 360,
                jpeg_quality: 48,
                frames_per_second: 10,
            },
            Self::LowBandwidth => QualityProfile {
                maximum_width: 480,
                maximum_height: 270,
                jpeg_quality: 35,
                frames_per_second: 3,
            },
        }
    }
}

/// A bounded, local adaptation policy. It never turns on a hardware encoder:
/// that needs separate detection and a successful platform verification.
#[derive(Clone, Debug)]
pub struct QualityController {
    requested: QualityMode,
    auto_level: u8,
    consecutive_healthy_frames: u8,
}

impl QualityController {
    pub fn new(requested: QualityMode) -> Self {
        Self {
            requested,
            auto_level: 1,
            consecutive_healthy_frames: 0,
        }
    }

    pub fn set_requested(&mut self, requested: QualityMode) {
        self.requested = requested;
        self.auto_level = 1;
        self.consecutive_healthy_frames = 0;
    }

    pub fn profile(&self) -> QualityProfile {
        if self.requested != QualityMode::Auto {
            return self.requested.profile();
        }
        match self.auto_level {
            0 => QualityMode::ClearText.profile(),
            1 => QualityMode::Auto.profile(),
            _ => QualityMode::LowBandwidth.profile(),
        }
    }

    pub fn observe(&mut self, encode_ms: u64, sent: bool) {
        if self.requested != QualityMode::Auto {
            return;
        }
        let frame_budget_ms = 1_000 / u64::from(self.profile().frames_per_second);
        if !sent || encode_ms > frame_budget_ms {
            self.auto_level = self.auto_level.saturating_add(1).min(2);
            self.consecutive_healthy_frames = 0;
        } else {
            self.consecutive_healthy_frames = self.consecutive_healthy_frames.saturating_add(1);
            if self.consecutive_healthy_frames >= 30 && self.auto_level > 0 {
                self.auto_level -= 1;
                self.consecutive_healthy_frames = 0;
            }
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MonitorDescriptor {
    pub id: u32,
    pub name: String,
    pub x: i32,
    pub y: i32,
    pub width: u32,
    pub height: u32,
    pub scale_factor: f32,
    pub primary: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DesktopCapabilities {
    pub platform: String,
    pub monitors: Vec<MonitorDescriptor>,
    pub capture: String,
    pub input: String,
    pub encoder: String,
    pub hardware_encoder_verified: bool,
    pub keyboard_layout: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PointerButton {
    Left,
    Middle,
    Right,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyboardKey {
    Alt,
    Backspace,
    Control,
    Delete,
    Down,
    End,
    Enter,
    Escape,
    Home,
    Left,
    Meta,
    PageDown,
    PageUp,
    Right,
    Shift,
    Tab,
    Up,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum DesktopInput {
    Pointer {
        x: f32,
        y: f32,
    },
    Button {
        button: PointerButton,
        pressed: bool,
    },
    Scroll {
        horizontal: i32,
        vertical: i32,
        smooth: bool,
    },
    Key {
        key: KeyboardKey,
        pressed: bool,
    },
    Text {
        text: String,
    },
    ReleaseAll,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum DesktopMessage {
    Hello {
        version: u8,
        control_requested: bool,
        quality: QualityMode,
    },
    /// Advisory capability state for the controller UI. The host still
    /// checks `desktop.control` afresh for every input event.
    Control {
        allowed: bool,
    },
    Monitor {
        monitor: MonitorDescriptor,
        keyboard_layout: String,
    },
    Frame {
        sequence: u64,
        width: u32,
        height: u32,
        jpeg: String,
    },
    Input {
        sequence: u64,
        input: DesktopInput,
    },
    Quality {
        quality: QualityMode,
    },
    Stats {
        captured_frames: u64,
        sent_frames: u64,
        dropped_frames: u64,
        encode_ms: u64,
    },
    Disconnect {
        reason: String,
    },
}

#[derive(Clone, Debug)]
pub struct CapturedFrame {
    pub width: u32,
    pub height: u32,
    pub jpeg: Vec<u8>,
}

fn validate_input(input: &DesktopInput) -> Result<()> {
    match input {
        DesktopInput::Pointer { x, y }
            if x.is_finite()
                && y.is_finite()
                && (0.0..=1.0).contains(x)
                && (0.0..=1.0).contains(y) =>
        {
            Ok(())
        }
        DesktopInput::Button { .. } | DesktopInput::ReleaseAll => Ok(()),
        DesktopInput::Scroll {
            horizontal,
            vertical,
            ..
        } if horizontal.unsigned_abs() <= 1_000 && vertical.unsigned_abs() <= 1_000 => Ok(()),
        DesktopInput::Key { .. } => Ok(()),
        DesktopInput::Text { text }
            if !text.is_empty() && text.len() <= MAX_INPUT_TEXT_BYTES && !text.contains('\0') =>
        {
            Ok(())
        }
        _ => Err(AgentError::InvalidDesktopMessage),
    }
}

fn validate_message(message: &DesktopMessage) -> Result<()> {
    match message {
        DesktopMessage::Hello { version, .. } if *version == DESKTOP_PROTOCOL_VERSION => Ok(()),
        DesktopMessage::Control { .. } => Ok(()),
        DesktopMessage::Monitor {
            monitor,
            keyboard_layout,
        } if monitor.width > 0
            && monitor.height > 0
            && monitor.name.len() <= 160
            && monitor.scale_factor.is_finite()
            && monitor.scale_factor > 0.0
            && keyboard_layout.len() <= 80 =>
        {
            Ok(())
        }
        DesktopMessage::Frame {
            sequence,
            width,
            height,
            jpeg,
        } if *sequence > 0
            && *width > 0
            && *height > 0
            && jpeg.len() <= MAX_DESKTOP_JPEG_BYTES * 2
            && STANDARD_NO_PAD
                .decode(jpeg)
                .is_ok_and(|bytes| bytes.len() > 3 && bytes.len() <= MAX_DESKTOP_JPEG_BYTES) =>
        {
            Ok(())
        }
        DesktopMessage::Input { sequence, input } if *sequence > 0 => validate_input(input),
        DesktopMessage::Quality { .. } => Ok(()),
        DesktopMessage::Stats { .. } => Ok(()),
        DesktopMessage::Disconnect { reason } if reason.len() <= 160 => Ok(()),
        _ => Err(AgentError::InvalidDesktopMessage),
    }
}

pub fn encode_desktop_message(message: &DesktopMessage) -> Result<Vec<u8>> {
    validate_message(message)?;
    let bytes = serde_json::to_vec(message).map_err(|_| AgentError::InvalidDesktopMessage)?;
    if bytes.is_empty() || bytes.len() > MAX_DESKTOP_MESSAGE_BYTES {
        return Err(AgentError::InvalidDesktopMessage);
    }
    Ok(bytes)
}

pub fn decode_desktop_message(bytes: &[u8]) -> Result<DesktopMessage> {
    if bytes.is_empty() || bytes.len() > MAX_DESKTOP_MESSAGE_BYTES {
        return Err(AgentError::InvalidDesktopMessage);
    }
    let message: DesktopMessage =
        serde_json::from_slice(bytes).map_err(|_| AgentError::InvalidDesktopMessage)?;
    validate_message(&message)?;
    Ok(message)
}

#[cfg(target_os = "macos")]
mod platform {
    use super::*;
    use enigo::{Axis, Button, Coordinate, Direction, Enigo, Key, Keyboard, Mouse, Settings};
    use image::{codecs::jpeg::JpegEncoder, imageops::FilterType, ExtendedColorType};
    use xcap::Monitor;

    pub struct NativeDesktopHost {
        monitor: Monitor,
        descriptor: MonitorDescriptor,
        input: Option<Enigo>,
        held_keys: HashSet<KeyboardKey>,
        held_buttons: HashSet<PointerButton>,
    }

    fn monitor_descriptor(monitor: &Monitor) -> Result<MonitorDescriptor> {
        Ok(MonitorDescriptor {
            id: monitor
                .id()
                .map_err(|error| AgentError::DesktopCapabilityUnavailable(error.to_string()))?,
            name: monitor
                .friendly_name()
                .or_else(|_| monitor.name())
                .map_err(|error| AgentError::DesktopCapabilityUnavailable(error.to_string()))?,
            x: monitor
                .x()
                .map_err(|error| AgentError::DesktopCapabilityUnavailable(error.to_string()))?,
            y: monitor
                .y()
                .map_err(|error| AgentError::DesktopCapabilityUnavailable(error.to_string()))?,
            width: monitor
                .width()
                .map_err(|error| AgentError::DesktopCapabilityUnavailable(error.to_string()))?,
            height: monitor
                .height()
                .map_err(|error| AgentError::DesktopCapabilityUnavailable(error.to_string()))?,
            scale_factor: monitor
                .scale_factor()
                .map_err(|error| AgentError::DesktopCapabilityUnavailable(error.to_string()))?,
            primary: monitor
                .is_primary()
                .map_err(|error| AgentError::DesktopCapabilityUnavailable(error.to_string()))?,
        })
    }

    pub fn capabilities() -> Result<DesktopCapabilities> {
        let monitors = Monitor::all().map_err(|error| {
            AgentError::DesktopCapabilityUnavailable(format!(
                "macos_monitor_enumeration_failed: {error}"
            ))
        })?;
        let monitors = monitors
            .iter()
            .map(monitor_descriptor)
            .collect::<Result<Vec<_>>>()?;
        Ok(DesktopCapabilities {
            platform: "macos".into(),
            monitors,
            capture: "screen_recording_permission_required".into(),
            input: "accessibility_permission_required".into(),
            encoder: "bounded_software_jpeg".into(),
            hardware_encoder_verified: false,
            keyboard_layout: "system_unicode_text_and_named_keys".into(),
        })
    }

    impl NativeDesktopHost {
        pub fn open(monitor_id: Option<u32>) -> Result<Self> {
            let monitors = Monitor::all().map_err(|error| {
                AgentError::DesktopCapabilityUnavailable(format!(
                    "macos_screen_recording_unavailable: {error}"
                ))
            })?;
            let monitor = monitors
                .into_iter()
                .find(|candidate| {
                    monitor_id.map_or_else(
                        || candidate.is_primary().unwrap_or(false),
                        |id| candidate.id().is_ok_and(|candidate_id| candidate_id == id),
                    )
                })
                .ok_or_else(|| {
                    AgentError::DesktopCapabilityUnavailable("requested_monitor_not_found".into())
                })?;
            let descriptor = monitor_descriptor(&monitor)?;
            Ok(Self {
                monitor,
                descriptor,
                input: None,
                held_keys: HashSet::new(),
                held_buttons: HashSet::new(),
            })
        }

        pub fn descriptor(&self) -> MonitorDescriptor {
            self.descriptor.clone()
        }

        /// xcap's macOS bounds and Enigo's Quartz events both use display
        /// points, while captured frames can be Retina pixels. Keeping the
        /// controller coordinate normalized means scale changes do not leak
        /// into input injection. Re-enumerate to catch a changed point bounds,
        /// scale, or display removal before the next capture.
        pub fn refresh_monitor(&mut self) -> Result<Option<MonitorDescriptor>> {
            let monitors = Monitor::all().map_err(|error| {
                AgentError::DesktopCapabilityUnavailable(format!(
                    "macos_monitor_refresh_failed: {error}"
                ))
            })?;
            let monitor = monitors
                .into_iter()
                .find(|candidate| candidate.id().is_ok_and(|id| id == self.descriptor.id))
                .ok_or_else(|| {
                    AgentError::DesktopCapabilityUnavailable("selected_monitor_removed".into())
                })?;
            let descriptor = monitor_descriptor(&monitor)?;
            if descriptor == self.descriptor {
                return Ok(None);
            }
            self.monitor = monitor;
            self.descriptor = descriptor.clone();
            Ok(Some(descriptor))
        }

        pub fn capture(&self, profile: QualityProfile) -> Result<CapturedFrame> {
            let image = self.monitor.capture_image().map_err(|error| {
                AgentError::DesktopCapabilityUnavailable(format!(
                    "macos_screen_recording_denied_or_capture_failed: {error}"
                ))
            })?;
            let (source_width, source_height) = image.dimensions();
            let scale = (profile.maximum_width as f32 / source_width as f32)
                .min(profile.maximum_height as f32 / source_height as f32)
                .min(1.0);
            let width = ((source_width as f32 * scale).round() as u32).max(1);
            let height = ((source_height as f32 * scale).round() as u32).max(1);
            let resized = image::imageops::resize(&image, width, height, FilterType::Triangle);
            let mut rgb = Vec::with_capacity(
                (width as usize)
                    .saturating_mul(height as usize)
                    .saturating_mul(3),
            );
            for pixel in resized.as_raw().chunks_exact(4) {
                rgb.extend_from_slice(&pixel[..3]);
            }
            let mut jpeg = Vec::new();
            JpegEncoder::new_with_quality(&mut jpeg, profile.jpeg_quality)
                .encode(&rgb, width, height, ExtendedColorType::Rgb8)
                .map_err(|error| {
                    AgentError::DesktopCapabilityUnavailable(format!(
                        "software_jpeg_encode_failed: {error}"
                    ))
                })?;
            if jpeg.len() > MAX_DESKTOP_JPEG_BYTES {
                return Err(AgentError::InvalidDesktopMessage);
            }
            Ok(CapturedFrame {
                width,
                height,
                jpeg,
            })
        }

        fn input(&mut self) -> Result<&mut Enigo> {
            if self.input.is_none() {
                self.input = Some(Enigo::new(&Settings::default()).map_err(|error| {
                    AgentError::DesktopCapabilityUnavailable(format!(
                        "macos_accessibility_denied_or_input_unavailable: {error}"
                    ))
                })?);
            }
            self.input.as_mut().ok_or(AgentError::DesktopControlDenied)
        }

        fn button(button: PointerButton) -> Button {
            match button {
                PointerButton::Left => Button::Left,
                PointerButton::Middle => Button::Middle,
                PointerButton::Right => Button::Right,
            }
        }

        fn key(key: KeyboardKey) -> Key {
            match key {
                KeyboardKey::Alt => Key::Alt,
                KeyboardKey::Backspace => Key::Backspace,
                KeyboardKey::Control => Key::Control,
                KeyboardKey::Delete => Key::Delete,
                KeyboardKey::Down => Key::DownArrow,
                KeyboardKey::End => Key::End,
                KeyboardKey::Enter => Key::Return,
                KeyboardKey::Escape => Key::Escape,
                KeyboardKey::Home => Key::Home,
                KeyboardKey::Left => Key::LeftArrow,
                KeyboardKey::Meta => Key::Meta,
                KeyboardKey::PageDown => Key::PageDown,
                KeyboardKey::PageUp => Key::PageUp,
                KeyboardKey::Right => Key::RightArrow,
                KeyboardKey::Shift => Key::Shift,
                KeyboardKey::Tab => Key::Tab,
                KeyboardKey::Up => Key::UpArrow,
            }
        }

        pub fn apply_input(&mut self, input: DesktopInput) -> Result<()> {
            validate_input(&input)?;
            match input {
                DesktopInput::Pointer { x, y } => {
                    let absolute_x = self.descriptor.x.saturating_add(
                        (x * self.descriptor.width.saturating_sub(1) as f32).round() as i32,
                    );
                    let absolute_y = self.descriptor.y.saturating_add(
                        (y * self.descriptor.height.saturating_sub(1) as f32).round() as i32,
                    );
                    self.input()?
                        .move_mouse(absolute_x, absolute_y, Coordinate::Abs)
                        .map_err(|error| {
                            AgentError::DesktopCapabilityUnavailable(error.to_string())
                        })?;
                }
                DesktopInput::Button { button, pressed } => {
                    self.input()?
                        .button(
                            Self::button(button),
                            if pressed {
                                Direction::Press
                            } else {
                                Direction::Release
                            },
                        )
                        .map_err(|error| {
                            AgentError::DesktopCapabilityUnavailable(error.to_string())
                        })?;
                    if pressed {
                        self.held_buttons.insert(button);
                    } else {
                        self.held_buttons.remove(&button);
                    }
                }
                DesktopInput::Scroll {
                    horizontal,
                    vertical,
                    smooth,
                } => {
                    let input = self.input()?;
                    if smooth {
                        input
                            .smooth_scroll(horizontal, Axis::Horizontal)
                            .map_err(|error| {
                                AgentError::DesktopCapabilityUnavailable(error.to_string())
                            })?;
                        input
                            .smooth_scroll(vertical, Axis::Vertical)
                            .map_err(|error| {
                                AgentError::DesktopCapabilityUnavailable(error.to_string())
                            })?;
                    } else {
                        input
                            .scroll(horizontal, Axis::Horizontal)
                            .map_err(|error| {
                                AgentError::DesktopCapabilityUnavailable(error.to_string())
                            })?;
                        input.scroll(vertical, Axis::Vertical).map_err(|error| {
                            AgentError::DesktopCapabilityUnavailable(error.to_string())
                        })?;
                    }
                }
                DesktopInput::Key { key, pressed } => {
                    self.input()?
                        .key(
                            Self::key(key),
                            if pressed {
                                Direction::Press
                            } else {
                                Direction::Release
                            },
                        )
                        .map_err(|error| {
                            AgentError::DesktopCapabilityUnavailable(error.to_string())
                        })?;
                    if pressed {
                        self.held_keys.insert(key);
                    } else {
                        self.held_keys.remove(&key);
                    }
                }
                DesktopInput::Text { text } => self
                    .input()?
                    .text(&text)
                    .map_err(|error| AgentError::DesktopCapabilityUnavailable(error.to_string()))?,
                DesktopInput::ReleaseAll => self.release_all()?,
            }
            Ok(())
        }

        /// Ask macOS for Accessibility permission without injecting any event.
        pub fn verify_input_permission(&mut self) -> Result<()> {
            let _ = self.input()?;
            Ok(())
        }

        pub fn release_all(&mut self) -> Result<()> {
            let keys = self.held_keys.drain().collect::<Vec<_>>();
            let buttons = self.held_buttons.drain().collect::<Vec<_>>();
            if let Some(input) = self.input.as_mut() {
                for key in keys {
                    input
                        .key(Self::key(key), Direction::Release)
                        .map_err(|error| {
                            AgentError::DesktopCapabilityUnavailable(error.to_string())
                        })?;
                }
                for button in buttons {
                    input
                        .button(Self::button(button), Direction::Release)
                        .map_err(|error| {
                            AgentError::DesktopCapabilityUnavailable(error.to_string())
                        })?;
                }
            }
            Ok(())
        }
    }
}

#[cfg(not(target_os = "macos"))]
mod platform {
    use super::*;

    pub struct NativeDesktopHost;

    pub fn capabilities() -> Result<DesktopCapabilities> {
        Ok(DesktopCapabilities {
            platform: std::env::consts::OS.into(),
            monitors: vec![],
            capture: "unsupported_runtime_adapter".into(),
            input: "unsupported_runtime_adapter".into(),
            encoder: "unavailable".into(),
            hardware_encoder_verified: false,
            keyboard_layout: "unavailable".into(),
        })
    }

    impl NativeDesktopHost {
        pub fn open(_: Option<u32>) -> Result<Self> {
            Err(AgentError::DesktopCapabilityUnavailable(
                "desktop_capture_and_input_runtime_adapter_not_yet_validated_for_this_platform"
                    .into(),
            ))
        }
        pub fn descriptor(&self) -> MonitorDescriptor {
            unreachable!()
        }
        pub fn refresh_monitor(&mut self) -> Result<Option<MonitorDescriptor>> {
            Err(AgentError::DesktopCapabilityUnavailable(
                "screen_capture_unsupported".into(),
            ))
        }
        pub fn capture(&self, _: QualityProfile) -> Result<CapturedFrame> {
            Err(AgentError::DesktopCapabilityUnavailable(
                "screen_capture_unsupported".into(),
            ))
        }
        pub fn apply_input(&mut self, _: DesktopInput) -> Result<()> {
            Err(AgentError::DesktopCapabilityUnavailable(
                "input_injection_unsupported".into(),
            ))
        }
        pub fn verify_input_permission(&mut self) -> Result<()> {
            Err(AgentError::DesktopCapabilityUnavailable(
                "input_injection_unsupported".into(),
            ))
        }
        pub fn release_all(&mut self) -> Result<()> {
            Ok(())
        }
    }
}

pub use platform::{capabilities, NativeDesktopHost};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn desktop_wire_rejects_arbitrary_commands_oversized_frames_and_bad_coordinates() {
        assert!(decode_desktop_message(br#"{"type":"exec","command":"id"}"#).is_err());
        assert!(decode_desktop_message(&vec![b'x'; MAX_DESKTOP_MESSAGE_BYTES + 1]).is_err());
        assert!(encode_desktop_message(&DesktopMessage::Input {
            sequence: 1,
            input: DesktopInput::Pointer { x: 1.1, y: 0.5 }
        })
        .is_err());
        assert!(matches!(
            decode_desktop_message(br#"{"type":"control","allowed":true}"#),
            Ok(DesktopMessage::Control { allowed: true })
        ));
        assert!(encode_desktop_message(&DesktopMessage::Input {
            sequence: 1,
            input: DesktopInput::Text { text: "\0".into() }
        })
        .is_err());
    }

    #[test]
    fn auto_quality_degrades_on_backpressure_and_recovers_only_after_a_bounded_healthy_window() {
        let mut quality = QualityController::new(QualityMode::Auto);
        assert_eq!(quality.profile().maximum_width, 640);
        quality.observe(500, false);
        assert_eq!(quality.profile().maximum_width, 480);
        for _ in 0..30 {
            quality.observe(1, true);
        }
        assert_eq!(quality.profile().maximum_width, 640);
    }
}
