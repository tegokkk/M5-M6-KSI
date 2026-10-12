import express from 'express';
import multer from 'multer';
import { DatabaseSync } from 'node:sqlite';
import { randomBytes, randomUUID, scryptSync, timingSafeEqual } from 'node:crypto';
import { mkdirSync, unlinkSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.dirname(fileURLToPath(import.meta.url));
const DATA_DIR = path.join(ROOT, 'data');
const UPLOAD_DIR = path.join(DATA_DIR, 'uploads');
const PUBLIC_DIR = path.join(ROOT, 'public');
const PORT = Number(process.env.PORT || 3000);
const HOST = process.env.HOST || '0.0.0.0'; // Bind to all interfaces for cloud deployment.
mkdirSync(UPLOAD_DIR, { recursive: true });

const db = new DatabaseSync(path.join(DATA_DIR, 'ruangkampus.sqlite'));
db.exec(`
  PRAGMA foreign_keys = ON;
  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY, name TEXT NOT NULL, email TEXT NOT NULL UNIQUE,
    password_salt TEXT NOT NULL, password_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('student','lecturer','admin')),
    program TEXT NOT NULL, initials TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS grades (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    student_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    course TEXT NOT NULL, code TEXT NOT NULL, lecturer TEXT NOT NULL,
    score INTEGER NOT NULL CHECK(score BETWEEN 0 AND 100), letter TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS discussions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    author_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    body TEXT NOT NULL, created_at TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS submissions (
    id TEXT PRIMARY KEY, student_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    title TEXT NOT NULL, original_name TEXT NOT NULL, stored_name TEXT NOT NULL,
    uploaded_at TEXT NOT NULL
  );
`);

const passwordRecord = (password) => {
  const salt = randomBytes(16).toString('hex');
  const hash = scryptSync(password, salt, 64).toString('hex');
  return { salt, hash };
};
function seedUser(user) {
  const record = passwordRecord(user.password);
  db.prepare(`INSERT OR IGNORE INTO users
    (id,name,email,password_salt,password_hash,role,program,initials)
    VALUES (?,?,?,?,?,?,?,?)`).run(user.id,user.name,user.email,record.salt,record.hash,user.role,user.program,user.initials);
}
[
  {id:'mhs-1042',name:'Tego Saputra',email:'tegosaputra@demo.test',password:'mahasiswa123',role:'student',program:'Sistem Informasi',initials:'TS'},
  {id:'mhs-1088',name:'Raka Pratama',email:'raka@demo.test',password:'raka12345',role:'student',program:'Desain Komunikasi Visual',initials:'RP'},
  {id:'dsn-0201',name:'Reza Redo',email:'rezaredo@demo.test',password:'dosen123',role:'lecturer',program:'Dosen · Informatika',initials:'RR'},
  {id:'adm-0001',name:'Ayu Maharani',email:'admin@demo.test',password:'admin123',role:'admin',program:'Administrator',initials:'AM'}
].forEach(seedUser);

const countRows = (table) => db.prepare(`SELECT COUNT(*) AS count FROM ${table}`).get().count;
if (countRows('grades') === 0) {
  const add = db.prepare('INSERT INTO grades (student_id,course,code,lecturer,score,letter) VALUES (?,?,?,?,?,?)');
  [
    ['mhs-1042','Basis Data','IF204','Reza Redo',88,'A-'],
    ['mhs-1042','Interaksi Manusia & Komputer','SI216','Dina Puspita',92,'A'],
    ['mhs-1042','Pemrograman Web','IF221','Reza Redo',84,'B+'],
    ['mhs-1042','Analisis Proses Bisnis','SI208','Rendi Saputra',90,'A-'],
    ['mhs-1088','Basis Data','IF204','Reza Redo',77,'B+'],
    ['mhs-1088','Pemrograman Web','IF221','Reza Redo',81,'A-']
  ].forEach(row=>add.run(...row));
}
if (countRows('discussions') === 0) {
  const add = db.prepare('INSERT INTO discussions (author_id,body,created_at) VALUES (?,?,?)');
  add.run('dsn-0201','Selamat datang di ruang diskusi RuangKampus. Pekan ini, bagikan contoh antarmuka yang menurut kalian mudah digunakan.','2026-10-12T08:20:00.000Z');
  add.run('mhs-1088','Saya suka katalog perpustakaan digital karena filter dan kategori bukunya jelas.','2026-10-12T09:05:00.000Z');
}

const app = express();
app.disable('x-powered-by');
app.use(express.json({ limit: '100kb' }));
app.use(express.urlencoded({ extended: false, limit: '100kb' }));
const sessions = new Map();
function readCookie(req, name) {
  const found = (req.headers.cookie || '').split(';').map(v=>v.trim()).find(v=>v.startsWith(`${name}=`));
  return found ? decodeURIComponent(found.slice(name.length + 1)) : null;
}
app.use((req,_res,next)=>{
  const token=readCookie(req,'rk_session');
  const saved=token && sessions.get(token);
  if(saved && saved.expiresAt>Date.now()){
    req.sessionToken=token;
    req.user=db.prepare('SELECT id,name,email,role,program,initials FROM users WHERE id=?').get(saved.userId)||null;
    saved.expiresAt=Date.now()+8*60*60*1000;
  } else if(token) sessions.delete(token);
  next();
});
const requireLogin=(req,res,next)=>req.user?next():res.status(401).json({error:'Silakan masuk terlebih dahulu.'});
const allowRoles=(...roles)=>(req,res,next)=>roles.includes(req.user?.role)?next():res.status(403).json({error:'Akses ditolak untuk peran ini.'});
const publicUser=(u)=>({id:u.id,name:u.name,email:u.email,role:u.role,program:u.program,initials:u.initials});
const letter=(n)=>n>=90?'A':n>=85?'A-':n>=80?'B+':n>=75?'B':n>=70?'B-':n>=65?'C+':n>=60?'C':'D';

app.get('/api/session',(req,res)=>req.user?res.json({user:req.user}):res.status(401).json({error:'Belum masuk.'}));
app.post('/api/login',(req,res)=>{
  const email=String(req.body?.email||'').trim().toLowerCase();
  const password=String(req.body?.password||'');
  if(!email||!password)return res.status(400).json({error:'Email dan kata sandi wajib diisi.'});
  // INTENTIONAL TRAINING GAP: this endpoint has no rate limit or lockout.
  const user=db.prepare('SELECT id,password_salt,password_hash FROM users WHERE email=?').get(email);
  if(!user)return res.status(401).json({error:'Email atau kata sandi salah.'});
  const candidate=scryptSync(password,user.password_salt,64);
  const expected=Buffer.from(user.password_hash,'hex');
  if(candidate.length!==expected.length||!timingSafeEqual(candidate,expected))return res.status(401).json({error:'Email atau kata sandi salah.'});
  const token=randomBytes(32).toString('hex');
  sessions.set(token,{userId:user.id,expiresAt:Date.now()+8*60*60*1000});
  res.setHeader('Set-Cookie',`rk_session=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=28800`);
  res.json({user:db.prepare('SELECT id,name,email,role,program,initials FROM users WHERE id=?').get(user.id)});
});
app.post('/api/logout',requireLogin,(req,res)=>{
  sessions.delete(req.sessionToken);
  res.setHeader('Set-Cookie','rk_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0');
  res.json({ok:true});
});

app.get('/api/students',requireLogin,(req,res)=>{
  res.json(db.prepare("SELECT id,name,program,initials FROM users WHERE role='student' ORDER BY name").all());
});
app.get('/api/grades',requireLogin,allowRoles('lecturer','admin'),(_req,res)=>{
  res.json(db.prepare(`SELECT g.id,g.student_id AS studentId,u.name AS student,g.course,g.code,g.lecturer,g.score,g.letter
    FROM grades g JOIN users u ON u.id=g.student_id ORDER BY u.name,g.course`).all());
});
app.get('/api/grades/:studentId',requireLogin,(req,res)=>{
  // INTENTIONAL IDOR: authenticated students may request another student's ID.
  const student=db.prepare("SELECT id,name,program FROM users WHERE id=? AND role='student'").get(req.params.studentId);
  if(!student)return res.status(404).json({error:'Mahasiswa tidak ditemukan.'});
  const rows=db.prepare('SELECT id,course,code,lecturer,score,letter FROM grades WHERE student_id=? ORDER BY course').all(student.id);
  res.json({student,grades:rows});
});
app.put('/api/grades/:gradeId',requireLogin,allowRoles('lecturer','admin'),(req,res)=>{
  const score=Number(req.body?.score);
  if(!Number.isInteger(score)||score<0||score>100)return res.status(400).json({error:'Nilai harus berupa bilangan bulat 0–100.'});
  const result=db.prepare('UPDATE grades SET score=?,letter=? WHERE id=?').run(score,letter(score),Number(req.params.gradeId));
  if(!result.changes)return res.status(404).json({error:'Entri nilai tidak ditemukan.'});
  res.json({ok:true});
});
app.post('/api/grades',requireLogin,allowRoles('lecturer','admin'),(req,res)=>{
  const {studentId,course,code}=req.body||{};const score=Number(req.body?.score);
  if(!studentId||!String(course||'').trim()||!String(code||'').trim()||!Number.isInteger(score)||score<0||score>100)return res.status(400).json({error:'Lengkapi mahasiswa, mata kuliah, kode, dan nilai 0–100.'});
  const student=db.prepare("SELECT id FROM users WHERE id=? AND role='student'").get(studentId);
  if(!student)return res.status(400).json({error:'Akun mahasiswa tidak valid.'});
  const result=db.prepare('INSERT INTO grades (student_id,course,code,lecturer,score,letter) VALUES (?,?,?,?,?,?)').run(studentId,String(course).trim(),String(code).trim(),req.user.name,score,letter(score));
  res.status(201).json({id:Number(result.lastInsertRowid)});
});

app.get('/api/discussions',requireLogin,(req,res)=>{
  const search=String(req.query.search||'').slice(0,140);
  let rows;
  if(search){
    // INTENTIONAL SQL INJECTION LAB: untrusted text is interpolated into this query.
    const sql=`SELECT d.id,d.body,d.created_at AS createdAt,u.name AS author,u.initials
      FROM discussions d JOIN users u ON u.id=d.author_id
      WHERE d.body LIKE '%${search}%'
      ORDER BY d.id DESC LIMIT 50`;
    try{rows=db.prepare(sql).all()}catch(error){return res.status(400).json({error:'Query diskusi gagal.',detail:error.message})}
  }else{
    rows=db.prepare(`SELECT d.id,d.body,d.created_at AS createdAt,u.name AS author,u.initials
      FROM discussions d JOIN users u ON u.id=d.author_id ORDER BY d.id DESC LIMIT 50`).all();
  }
  res.json(rows);
});
app.post('/api/discussions',requireLogin,(req,res)=>{
  const body=String(req.body?.body||'').trim();
  if(!body||body.length>500)return res.status(400).json({error:'Isi diskusi wajib diisi (maksimal 500 karakter).'});
  const result=db.prepare('INSERT INTO discussions (author_id,body,created_at) VALUES (?,?,?)').run(req.user.id,body,new Date().toISOString());
  res.status(201).json({id:Number(result.lastInsertRowid)});
});

const allowedFiles=new Map([
  ['.pdf','application/pdf'],['.txt','text/plain'],['.docx','application/vnd.openxmlformats-officedocument.wordprocessingml.document']
]);
const storage=multer.diskStorage({
  destination:(_req,_file,cb)=>cb(null,UPLOAD_DIR),
  filename:(_req,file,cb)=>cb(null,`${randomUUID()}${path.extname(file.originalname).toLowerCase()}`)
});
const upload=multer({storage,limits:{fileSize:8*1024*1024,files:1,fields:2},fileFilter:(_req,file,cb)=>{
  const ext=path.extname(file.originalname).toLowerCase();
  if(allowedFiles.get(ext)!==file.mimetype)return cb(new Error('Format yang diterima: PDF, TXT, atau DOCX.'));
  cb(null,true);
}});
app.get('/api/submissions',requireLogin,(req,res)=>{
  const isStaff=['lecturer','admin'].includes(req.user.role);
  const rows=isStaff?db.prepare(`SELECT s.id,s.student_id AS studentId,u.name AS student,s.title,s.original_name AS file,s.uploaded_at AS uploadedAt
    FROM submissions s JOIN users u ON u.id=s.student_id ORDER BY s.uploaded_at DESC`).all():db.prepare(`SELECT id,student_id AS studentId,title,original_name AS file,uploaded_at AS uploadedAt
    FROM submissions WHERE student_id=? ORDER BY uploaded_at DESC`).all(req.user.id);
  res.json(rows);
});
app.post('/api/submissions',requireLogin,allowRoles('student'),upload.single('assignment'),(req,res)=>{
  const title=String(req.body?.title||'').trim();
  if(!title||title.length>120){if(req.file)unlinkSync(req.file.path);return res.status(400).json({error:'Pilih mata kuliah atau judul tugas.'})}
  if(!req.file)return res.status(400).json({error:'Pilih berkas terlebih dahulu.'});
  const id=randomUUID();
  db.prepare('INSERT INTO submissions (id,student_id,title,original_name,stored_name,uploaded_at) VALUES (?,?,?,?,?,?)').run(id,req.user.id,title,path.basename(req.file.originalname),req.file.filename,new Date().toISOString());
  res.status(201).json({id});
});
app.get('/api/submissions/:id/file',requireLogin,(req,res)=>{
  const row=db.prepare('SELECT id,student_id,original_name,stored_name FROM submissions WHERE id=?').get(req.params.id);
  if(!row)return res.status(404).json({error:'Berkas tidak ditemukan.'});
  if(req.user.role==='student'&&row.student_id!==req.user.id)return res.status(403).json({error:'Berkas ini bukan milik akunmu.'});
  res.download(path.join(UPLOAD_DIR,row.stored_name),row.original_name);
});

app.get('/api/accounts',requireLogin,allowRoles('admin'),(_req,res)=>{
  res.json(db.prepare('SELECT id,name,email,role,program,initials FROM users ORDER BY role,name').all());
});
app.post('/api/accounts',requireLogin,allowRoles('admin'),(req,res)=>{
  const name=String(req.body?.name||'').trim();const email=String(req.body?.email||'').trim().toLowerCase();
  const password=String(req.body?.password||'');const role=String(req.body?.role||'');const program=String(req.body?.program||'Program demo').trim();
  if(name.length<2||!email.includes('@')||password.length<8||!['student','lecturer','admin'].includes(role))return res.status(400).json({error:'Periksa nama, email, peran, dan kata sandi (minimal 8 karakter).'});
  const id=`${role==='student'?'mhs':role==='lecturer'?'dsn':'adm'}-${randomBytes(3).toString('hex')}`;
  const {salt,hash}=passwordRecord(password);const initials=name.split(/\s+/).map(part=>part[0]).join('').slice(0,2).toUpperCase();
  try{db.prepare('INSERT INTO users (id,name,email,password_salt,password_hash,role,program,initials) VALUES (?,?,?,?,?,?,?,?)').run(id,name,email,salt,hash,role,program||'Program demo',initials)}catch{return res.status(409).json({error:'Email sudah digunakan.'})}
  res.status(201).json({id});
});
app.patch('/api/accounts/:id',requireLogin,allowRoles('admin'),(req,res)=>{
  const name=String(req.body?.name||'').trim();const program=String(req.body?.program||'').trim();
  if(name.length<2||program.length<2)return res.status(400).json({error:'Nama dan program/jabatan wajib diisi.'});
  const initials=name.split(/\s+/).map(part=>part[0]).join('').slice(0,2).toUpperCase();
  const result=db.prepare('UPDATE users SET name=?,program=?,initials=? WHERE id=?').run(name,program,initials,req.params.id);
  if(!result.changes)return res.status(404).json({error:'Akun tidak ditemukan.'});
  res.json({ok:true});
});
app.delete('/api/accounts/:id',requireLogin,allowRoles('admin'),(req,res)=>{
  if(req.params.id===req.user.id)return res.status(400).json({error:'Admin tidak dapat menghapus akunnya sendiri.'});
  const result=db.prepare('DELETE FROM users WHERE id=?').run(req.params.id);
  if(!result.changes)return res.status(404).json({error:'Akun tidak ditemukan.'});
  for(const [token,session] of sessions)if(session.userId===req.params.id)sessions.delete(token);
  res.json({ok:true});
});

app.use(express.static(PUBLIC_DIR,{index:'index.html',dotfiles:'ignore'}));
app.use('/api',(_req,res)=>res.status(404).json({error:'Endpoint API tidak ditemukan.'}));
app.use((error,_req,res,_next)=>{
  if(error instanceof multer.MulterError)return res.status(400).json({error:error.code==='LIMIT_FILE_SIZE'?'Ukuran maksimum berkas 8 MB.':'Unggahan tidak valid.'});
  if(error) return res.status(400).json({error:error.message||'Permintaan tidak dapat diproses.'});
  res.status(500).json({error:'Terjadi kesalahan server.'});
});

const server=app.listen(PORT,HOST,()=>{
  console.log(`RuangKampus aktif: http://${HOST}:${PORT}`);
  console.log('Lab lokal dengan data sintetis; server hanya listen pada 127.0.0.1.');
  console.log('Akun demo: tegosaputra@demo.test, rezaredo@demo.test, admin@demo.test');
});
function shutdown(){server.close(()=>{db.close();process.exit(0)})}
process.on('SIGINT',shutdown);process.on('SIGTERM',shutdown);
