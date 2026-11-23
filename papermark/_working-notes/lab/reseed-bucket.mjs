// Recreate the lab bucket in LocalStack and put a marker object for every
// storage key the seeded database references. LocalStack is ephemeral, so
// this has to run after every container restart. Run inside pm-audit-app.
import { readFileSync } from "node:fs";
import { S3Client, CreateBucketCommand, PutObjectCommand, ListObjectsV2Command } from "@aws-sdk/client-s3";
import pg from "pg";

const env = Object.fromEntries(
  readFileSync("/app/.env", "utf8").split("\n").filter((l) => /^[A-Z_]+=/.test(l))
    .map((l) => { const i = l.indexOf("="); return [l.slice(0, i), l.slice(i + 1).trim().replace(/^"|"$/g, "")]; }),
);
const s3 = new S3Client({
  region: env.NEXT_PRIVATE_UPLOAD_REGION || "us-east-1",
  endpoint: env.NEXT_PRIVATE_UPLOAD_ENDPOINT,
  credentials: { accessKeyId: env.NEXT_PRIVATE_UPLOAD_ACCESS_KEY_ID, secretAccessKey: env.NEXT_PRIVATE_UPLOAD_SECRET_ACCESS_KEY },
});
const Bucket = env.NEXT_PRIVATE_UPLOAD_BUCKET;
try { await s3.send(new CreateBucketCommand({ Bucket })); console.log("bucket created", Bucket); } catch (e) { console.log("bucket:", e.name); }

const pool = new pg.Pool({ connectionString: env.POSTGRES_PRISMA_URL.replace(/[?&]connection_limit=\d+/, "") });
const { rows: versions } = await pool.query(
  `select dv.file, d.name, d."teamId" from "DocumentVersion" dv join "Document" d on d.id=dv."documentId"`);
const { rows: pages } = await pool.query(
  `select p.file, p."pageNumber", d.name, d."teamId" from "DocumentPage" p join "DocumentVersion" dv on dv.id=p."versionId" join "Document" d on d.id=dv."documentId"`);
await pool.end();

const seen = new Set();
async function put(Key, Body, ContentType) {
  if (!Key || seen.has(Key) || Key.startsWith("http")) return;
  seen.add(Key);
  await s3.send(new PutObjectCommand({ Bucket, Key, Body, ContentType }));
  console.log("put", Key);
}
for (const v of versions) {
  const team = v.teamId;
  const marker = `MARKER team=${team} doc="${v.name}" key=${v.file} ORIGINAL FILE - CONFIDENTIAL\n`;
  await put(v.file, marker, "application/pdf");
}
for (const p of pages) {
  const marker = `MARKER team=${p.teamId} doc="${p.name}" page=${p.pageNumber} key=${p.file}\n`;
  await put(p.file, marker, p.file.endsWith(".png") ? "image/png" : "image/jpeg");
}
const r = await s3.send(new ListObjectsV2Command({ Bucket }));
console.log("objects now:", (r.Contents ?? []).length);
