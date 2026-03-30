import net from 'node:net';
import type { KerizonWitness } from '../witness.js';

export function createWitnessTcpServer(witness: KerizonWitness): net.Server {
  return net.createServer((socket) => {
    socket.on('data', async (data) => {
      const result = await witness.processEvent(new Uint8Array(data));
      if ('receipt' in result) {
        socket.write(result.receipt);
      }
    });
  });
}
