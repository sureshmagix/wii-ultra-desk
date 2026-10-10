import { WebSocket } from 'ws';
import { createDevelopmentIdentity, signAuthProof } from '../../packages/protocol/identity.mjs';

export class CoordinatorClient {
  #messages = [];
  #waiters = [];

  constructor(url, identity = createDevelopmentIdentity()) {
    this.url = url;
    this.identity = identity;
    this.socket = new WebSocket(url);
    this.open = new Promise((resolve, reject) => {
      this.socket.once('open', resolve);
      this.socket.once('error', reject);
    });
    this.socket.on('message', raw => this.#receive(JSON.parse(raw.toString('utf8'))));
  }

  #receive(message) {
    const index = this.#waiters.findIndex(waiter => waiter.predicate(message));
    if (index >= 0) {
      const [waiter] = this.#waiters.splice(index, 1);
      clearTimeout(waiter.timer);
      waiter.resolve(message);
    } else this.#messages.push(message);
  }

  async send(message) {
    await this.open;
    this.socket.send(JSON.stringify(message));
  }

  waitFor(predicate, timeoutMs = 1_500) {
    const existing = this.#messages.findIndex(predicate);
    if (existing >= 0) return Promise.resolve(this.#messages.splice(existing, 1)[0]);
    return new Promise((resolve, reject) => {
      const waiter = {
        predicate,
        resolve,
        timer: setTimeout(() => {
          const index = this.#waiters.indexOf(waiter);
          if (index >= 0) this.#waiters.splice(index, 1);
          reject(new Error('Timed out waiting for coordinator message'));
        }, timeoutMs)
      };
      this.#waiters.push(waiter);
    });
  }

  waitForType(type, timeoutMs) {
    return this.waitFor(message => message.type === type, timeoutMs);
  }

  async authenticate() {
    await this.send({ type: 'AUTH_BEGIN', bundle: this.identity.bundle });
    const challenge = await this.waitForType('AUTH_CHALLENGE');
    await this.send({
      type: 'AUTH_PROVE',
      connectionId: challenge.connectionId,
      nonce: challenge.nonce,
      expiresAt: challenge.expiresAt,
      signature: signAuthProof(this.identity, {
        connectionId: challenge.connectionId,
        nonce: challenge.nonce,
        locator: this.identity.bundle.locator,
        fingerprint: this.identity.fingerprint,
        expiresAt: challenge.expiresAt
      })
    });
    return this.waitFor(message => message.type === 'AUTH_OK' || message.type === 'ERROR');
  }

  async close() {
    if (this.socket.readyState === WebSocket.CLOSED) return;
    const closed = new Promise(resolve => this.socket.once('close', resolve));
    this.socket.close();
    await closed;
  }
}
