const fs = require("node:fs");
const path = require("node:path");

class JsonSessions extends Map {
  constructor(filename) {
    super();
    this.filename = filename;
    if (fs.existsSync(filename)) {
      const records = JSON.parse(fs.readFileSync(filename, "utf8"));
      for (const [token, session] of Object.entries(records)) super.set(token, session);
    }
  }

  save() {
    fs.mkdirSync(path.dirname(this.filename), { recursive: true });
    const temporary = `${this.filename}.tmp`;
    fs.writeFileSync(temporary, JSON.stringify(Object.fromEntries(this), null, 2), { mode: 0o600 });
    fs.renameSync(temporary, this.filename);
  }

  set(key, value) { super.set(key, value); this.save(); return this; }
  delete(key) { const deleted = super.delete(key); if (deleted) this.save(); return deleted; }
}

module.exports = { JsonSessions };
