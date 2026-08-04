import { createServer } from "./api/server.js";

const PORT = Number(process.env.PORT ?? 4173);
const HOST = process.env.HOST ?? "127.0.0.1";
const app = createServer();
app.listen(PORT, HOST, () => {
  console.log(`Email Shield listening on http://${HOST}:${PORT}`);
});
