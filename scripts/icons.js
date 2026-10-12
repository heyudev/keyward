import { deflateSync } from 'node:zlib';
import { crc32 } from './archive.js';

/** Draw the existing lock motif at each required size without image dependencies. */
export function lockIcon(size) {
  const rows = Buffer.alloc(size * (size * 4 + 1));
  for (let y = 0; y < size; y++) {
    for (let x = 0; x < size; x++) {
      const nx = (x + .5) / size;
      const ny = (y + .5) / size;
      const round = Math.hypot(Math.max(.15 - nx, nx - .85, 0), Math.max(.15 - ny, ny - .85, 0)) <= .15;
      const shackle = Math.abs(Math.hypot(nx - .5, ny - .4) - .17) < .035 && ny < .43;
      const body = nx > .26 && nx < .74 && ny > .4 && ny < .78;
      const hole = Math.hypot(nx - .5, ny - .56) < .045 || (Math.abs(nx - .5) < .025 && ny > .56 && ny < .67);
      const white = shackle || (body && !hole);
      const i = y * (size * 4 + 1) + 1 + x * 4;
      rows[i] = white ? 255 : 35;
      rows[i + 1] = white ? 255 : 91;
      rows[i + 2] = white ? 255 : 212;
      rows[i + 3] = round ? 255 : 0;
    }
  }
  const chunk = (type, data) => {
    const name = Buffer.from(type);
    const length = Buffer.alloc(4);
    length.writeUInt32BE(data.length);
    const crc = Buffer.alloc(4);
    crc.writeUInt32BE(crc32(Buffer.concat([name, data])));
    return Buffer.concat([length, name, data, crc]);
  };
  const header = Buffer.alloc(13);
  header.writeUInt32BE(size, 0);
  header.writeUInt32BE(size, 4);
  header[8] = 8;
  header[9] = 6;
  return Buffer.concat([
    Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]),
    chunk('IHDR', header), chunk('IDAT', deflateSync(rows)), chunk('IEND', Buffer.alloc(0)),
  ]);
}
