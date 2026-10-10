import { WebSocket } from 'ws';
import { createCoordinator } from '../services/coordinator/server.mjs';
import { createDevelopmentIdentity, signAuthProof } from '../packages/protocol/identity.mjs';

class DeviceHarnessClient {
  constructor(url, label) {
    this.label = label;
    this.identity = createDevelopmentIdentity();
    this.socket = new WebSocket(url);
    this.messages = [];
    this.waiters = [];
    this.open = new Promise((resolve, reject) => {
      this.socket.once('open', resolve);
      this.socket.once('error', reject);
    });
    this.socket.on('message', raw => this.receive(JSON.parse(raw.toString('utf8'))));
  }

  receive(message) {
    const index = this.waiters.findIndex(waiter => waiter.predicate(message));
    if (index >= 0) {
      const waiter = this.waiters.splice(index, 1)[0];
      clearTimeout(waiter.timer);
      waiter.resolve(message);
    }
    else this.messages.push(message);
  }

  waitFor(type) {
    const index = this.messages.findIndex(message => message.type === type);
    if (index >= 0) return Promise.resolve(this.messages.splice(index, 1)[0]);
    return new Promise((resolve, reject) => {
      const waiter = { predicate: message => message.type === type, resolve, timer: undefined };
      this.waiters.push(waiter);
      waiter.timer = setTimeout(() => {
        const pending = this.waiters.indexOf(waiter);
        if (pending >= 0) {
          this.waiters.splice(pending, 1);
          reject(new Error(`${this.label} timed out waiting for ${type}`));
        }
      }, 2_000);
    });
  }

  async send(message) {
    await this.open;
    this.socket.send(JSON.stringify(message));
  }

  async authenticate() {
    await this.send({ type: 'AUTH_BEGIN', bundle: this.identity.bundle });
    const challenge = await this.waitFor('AUTH_CHALLENGE');
    await this.send({
      type: 'AUTH_PROVE', connectionId: challenge.connectionId, nonce: challenge.nonce, expiresAt: challenge.expiresAt,
      signature: signAuthProof(this.identity, {
        connectionId: challenge.connectionId, nonce: challenge.nonce, expiresAt: challenge.expiresAt,
        locator: this.identity.bundle.locator, fingerprint: this.identity.fingerprint
      })
    });
    const result = await this.waitFor('AUTH_OK');
    console.log(`${this.label}: authenticated locator ${result.locator}, fingerprint ${result.fingerprint}`);
  }

  close() {
    return new Promise(resolve => {
      if (this.socket.readyState === WebSocket.CLOSED) return resolve();
      this.socket.once('close', resolve);
      this.socket.close();
    });
  }
}

const coordinator = createCoordinator();
await new Promise(resolve => coordinator.listen(0, '127.0.0.1', resolve));
const url = `ws://127.0.0.1:${coordinator.address().port}/v1/connect`;
const host = new DeviceHarnessClient(url, 'Host development device');
const controller = new DeviceHarnessClient(url, 'Controller development device');

try {
  await host.authenticate();
  await controller.authenticate();
  await host.send({ type: 'PAIR_INVITE_CREATE', ttlMs: 60_000 });
  const invitation = await host.waitFor('PAIR_INVITE');
  await controller.send({ type: 'PAIR_REQUEST', token: invitation.token, bundle: controller.identity.bundle });
  const pending = await controller.waitFor('PAIR_PENDING');
  const request = await host.waitFor('PAIR_REQUEST');
  console.log(`Host received an attended pairing request for ${request.controller.fingerprint}.`);
  await host.send({ type: 'PAIR_APPROVE', pairingId: pending.pairingId });
  await controller.waitFor('PAIR_APPROVED');
  console.log('Host approval was required before opaque pairing frames could be relayed.');
  console.log('Harness stops before trust attestation: it does not run the native-agent Noise transport, compare a SAS, or claim pairing/session success.');
} finally {
  await Promise.all([host.close(), controller.close()]);
  await new Promise(resolve => coordinator.stop(resolve));
}
