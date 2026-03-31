import net from 'node:net';
import type { WitnessHandler, TransportServer } from '@kerizon/witness';

export function createTcpServer(handler: WitnessHandler): TransportServer {
  let server: net.Server;

  return {
    async listen(port: number) {
      server = net.createServer((socket) => {
        socket.on('data', async (data) => {
          const result = await handler.handleEventSubmission(new Uint8Array(data));
          if (result.status === 204) {
            socket.write(result.body ?? '');
          }
        });
      });
      await new Promise<void>((resolve) => server.listen(port, resolve));
    },
    async stop() {
      await new Promise<void>((resolve, reject) => server.close((err) => err ? reject(err) : resolve()));
    },
  };
}
