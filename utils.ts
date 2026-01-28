import { createWriteStream, existsSync, promises as fs } from "fs";
import https from "https";
import { dirname, resolve } from "path";

export const ARTIFACTS_DIR = resolve(process.cwd(), "circuit-artifacts");

const AWS_BASE_URL = "https://zk-shuffle.s3.us-east-1.amazonaws.com";
const ARTIFACT_PATHS = [
  "wasm/encrypt.wasm",
  "wasm/decrypt.wasm",
  "zkey/encrypt.zkey",
  "zkey/decrypt.zkey",
] as const;

async function downloadFile(remotePath: string, localPath: string) {
  await fs.mkdir(dirname(localPath), { recursive: true });

  if (existsSync(localPath)) {
    return;
  }

  await new Promise<void>((resolvePromise, reject) => {
    const file = createWriteStream(localPath);
    https
      .get(`${AWS_BASE_URL}/${remotePath}`, (resp) => {
        resp.pipe(file);
        file.on("finish", () => {
          file.close();
          resolvePromise();
        });
      })
      .on("error", (err) => {
        fs.unlink(localPath).catch(() => {});
        reject(err);
      });
  });
}

export async function ensureArtifactsDownloaded() {
  await fs.mkdir(ARTIFACTS_DIR, { recursive: true });
  const downloads = ARTIFACT_PATHS.map((artifact) =>
    downloadFile(artifact, resolve(ARTIFACTS_DIR, artifact)),
  );
  await Promise.all(downloads);
}
