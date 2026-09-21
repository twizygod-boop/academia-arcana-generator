import 'dotenv/config';
import express from 'express';
import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import PDFDocument from 'pdfkit';
import archiver from 'archiver';
import nodemailer from 'nodemailer';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const PORT = Number(process.env.PORT || 3000);
const STORAGE = path.join(__dirname, 'storage');
fs.mkdirSync(STORAGE, { recursive: true });

function verifyShopify(rawBody, hmac) {
  const secret = process.env.SHOPIFY_WEBHOOK_SECRET || '';
  if (!secret || !hmac) return false;
  const digest = crypto.createHmac('sha256', secret).update(rawBody).digest('base64');
  try { return crypto.timingSafeEqual(Buffer.from(digest), Buffer.from(hmac)); } catch { return false; }
}

function clean(value, fallback = '') {
  return String(value ?? fallback).replace(/[<>]/g, '').trim().slice(0, 120);
}

function lineProperties(item) {
  return Object.fromEntries((item.properties || []).map(p => [p.name, p.value]));
}

function houseData(house) {
  return {
    IGNIS: { title:'IGNIS', symbol:'I', element:'Feu', animal:'Phénix', traits:'Audace · Passion · Ambition' },
    NOCTIS: { title:'NOCTIS', symbol:'N', element:'Ombre', animal:'Corbeau', traits:'Intuition · Mystère · Stratégie' },
    SYLVA: { title:'SYLVA', symbol:'S', element:'Nature', animal:'Cerf', traits:'Harmonie · Patience · Sagesse' },
    AETHER: { title:'AETHER', symbol:'A', element:'Éther', animal:'Faucon', traits:'Curiosité · Créativité · Découverte' }
  }[house] || { title:'ARCANA', symbol:'A', element:'Éther', animal:'Hibou', traits:'Curiosité · Intuition · Courage' };
}

function drawHeader(doc, title) {
  doc.fillColor('#16121f').rect(0,0,595,842).fill();
  doc.fillColor('#d8b56a').font('Helvetica-Bold').fontSize(10).text('ACADEMIA ARCANA', 55, 55, {align:'center', width:485});
  doc.fillColor('#f4e8cc').font('Helvetica-Bold').fontSize(28).text(title, 55, 110, {align:'center', width:485});
  doc.fillColor('#8f7b55').moveTo(130,160).lineTo(465,160).stroke();
}

function drawFooter(doc) {
  doc.fillColor('#8f7b55').font('Helvetica').fontSize(8).text('Univers fictif original · Academia Arcana', 55, 805, {align:'center', width:485});
}

function createPdf(file, type, data) {
  return new Promise((resolve, reject) => {
    const doc = new PDFDocument({ size:'A4', margin:55 });
    const stream = fs.createWriteStream(file);
    doc.pipe(stream);
    const h = houseData(data.house);
    const fullName = `${data.firstName} ${data.lastName}`.trim() || 'Apprenti Arcana';

    if (type === 'letter') {
      drawHeader(doc, 'LETTRE D’ADMISSION');
      doc.fillColor('#f4e8cc').font('Helvetica').fontSize(13).text(`Cher ${fullName},`, 70, 210);
      doc.moveDown(1.2).text(`Les archives d’Academia Arcana ont retenu votre nom. Nous avons le plaisir de vous annoncer votre admission au sein de la maison ${h.title}.`, {width:455, lineGap:8});
      doc.moveDown(1).text(`Votre élément est ${h.element}. Votre animal tutélaire est le ${h.animal}. Les qualités qui vous accompagnent sont : ${h.traits}.`, {width:455, lineGap:8});
      doc.moveDown(1).text('Votre parcours commence maintenant. Gardez cette lettre précieusement : elle est la première page de votre histoire.', {width:455, lineGap:8});
      doc.moveDown(2).text('Le Conseil d’Arcana', {align:'right', width:455});
    } else if (type === 'certificate') {
      drawHeader(doc, 'CERTIFICAT D’ADMISSION');
      doc.fillColor('#f4e8cc').font('Helvetica').fontSize(13).text('Il est officiellement certifié que', 70, 220, {align:'center', width:455});
      doc.font('Helvetica-Bold').fontSize(30).fillColor('#d8b56a').text(fullName, 70, 270, {align:'center', width:455});
      doc.font('Helvetica').fontSize(14).fillColor('#f4e8cc').text(`a été admis à Academia Arcana dans la maison ${h.title}.`, 70, 330, {align:'center', width:455});
      doc.fontSize(12).fillColor('#c8bda6').text(`Élément : ${h.element}  ·  Animal : ${h.animal}`, 70, 390, {align:'center', width:455});
    } else if (type === 'profile') {
      drawHeader(doc, 'PROFIL MAGIQUE');
      const rows = [['Nom', fullName],['Maison',h.title],['Élément',h.element],['Animal tutélaire',h.animal],['Qualités',h.traits]];
      let y=220;
      rows.forEach(([a,b])=>{doc.fillColor('#8f7b55').font('Helvetica-Bold').fontSize(11).text(a,75,y);doc.fillColor('#f4e8cc').font('Helvetica').fontSize(13).text(b,220,y);y+=58;});
    } else {
      drawHeader(doc, 'PASSEPORT ARCANA');
      doc.fillColor('#d8b56a').font('Helvetica-Bold').fontSize(24).text(fullName, 70, 220, {align:'center', width:455});
      doc.fillColor('#f4e8cc').font('Helvetica').fontSize(14).text(`Maison ${h.title}`, 70, 275, {align:'center', width:455});
      doc.fontSize(12).fillColor('#c8bda6').text(`Élément : ${h.element}\nAnimal : ${h.animal}\nQualités : ${h.traits}`, 90, 340, {align:'center', width:415, lineGap:10});
      doc.fillColor('#8f7b55').fontSize(10).text('Passeport numérique personnalisé · À conserver dans vos archives', 70, 560, {align:'center', width:455});
    }
    drawFooter(doc); doc.end();
    stream.on('finish',()=>resolve(file)); stream.on('error',reject);
  });
}

async function zipFiles(files, target) {
  return new Promise((resolve,reject)=>{
    const output=fs.createWriteStream(target); const archive=archiver('zip',{zlib:{level:9}});
    output.on('close',()=>resolve(target)); archive.on('error',reject); archive.pipe(output);
    files.forEach(f=>archive.file(f,{name:path.basename(f)})); archive.finalize();
  });
}

function tokenFor(id) {
  const secret = process.env.DOWNLOAD_TOKEN_SECRET || 'change-me';
  return crypto.createHmac('sha256', secret).update(String(id)).digest('hex');
}

function mailer() {
  if (!process.env.SMTP_HOST) return null;
  return nodemailer.createTransport({host:process.env.SMTP_HOST,port:Number(process.env.SMTP_PORT||587),secure:String(process.env.SMTP_SECURE)==='true',auth:{user:process.env.SMTP_USER,pass:process.env.SMTP_PASS}});
}

async function processOrder(order) {
  const items = order.line_items || [];
  const personal = items.filter(i => lineProperties(i)._arcana_personalized === 'true');
  if (!personal.length) return;
  const first = lineProperties(personal[0]);
  const firstName = clean(first['Prénom'] || order.customer?.first_name || '');
  const lastName = clean(first['Nom'] || order.customer?.last_name || '');
  const house = clean(first['Maison'] || 'ARCANA').toUpperCase();
  const orderId = String(order.id);
  const dir = path.join(STORAGE, orderId); fs.mkdirSync(dir,{recursive:true});
  const files=[];
  for (const item of personal) {
    const props=lineProperties(item); const title=String(item.title||'').toLowerCase();
    let type='passport';
    if(title.includes('lettre')) type='letter'; else if(title.includes('certificat')) type='certificate'; else if(title.includes('profil')) type='profile';
    const count=Math.max(1,Number(item.quantity||1));
    for(let n=0;n<count;n++) { const file=path.join(dir,`${type}-${orderId}-${n+1}.pdf`); await createPdf(file,type,{firstName,lastName,house}); files.push(file); }
  }
  const bundle=path.join(dir,`Academia-Arcana-${firstName||'Apprenti'}-${lastName||orderId}.zip`);
  await zipFiles(files,bundle);
  const token=tokenFor(orderId); const link=`${process.env.BASE_URL}/download/${orderId}/${token}`;
  const recipient=order.email || order.customer?.email;
  const transport=mailer();
  if(transport && recipient){
    await transport.sendMail({from:process.env.MAIL_FROM,to:recipient,subject:'✨ Votre identité Academia Arcana est prête',text:`Votre création personnalisée est prête. Téléchargez-la ici : ${link}\n\nConservez ce lien précieusement.`,html:`<div style="font-family:Arial;background:#16121f;color:#f4e8cc;padding:32px"><h1>ACADEMIA ARCANA</h1><p>Votre création personnalisée est prête.</p><p><a href="${link}" style="display:inline-block;background:#d8b56a;color:#16121f;padding:14px 20px;text-decoration:none">Télécharger mon artefact</a></p></div>`});
  }
  console.log(`Order ${orderId}: generated ${bundle}; ${recipient ? 'email sent/attempted' : 'no email'}`);
}

app.get('/health',(req,res)=>res.json({ok:true,service:'academia-arcana-generator'}));
app.get('/download/:order/:token',(req,res)=>{
  if(req.params.token!==tokenFor(req.params.order)) return res.status(403).send('Lien invalide.');
  const dir=path.join(STORAGE,req.params.order); const files=fs.readdirSync(dir).filter(f=>f.endsWith('.zip')||f.endsWith('.pdf'));
  if(!files.length) return res.status(404).send('Fichier indisponible.');
  const preferred=files.find(f=>f.endsWith('.zip'))||files[0]; res.download(path.join(dir,preferred));
});

app.post('/webhooks/orders-paid', express.raw({type:'application/json'}), async (req,res)=>{
  const hmac=req.get('X-Shopify-Hmac-SHA256');
  if(!verifyShopify(req.body,hmac)) return res.status(401).send('Invalid HMAC');
  res.status(200).send('OK');
  try { await processOrder(JSON.parse(req.body.toString('utf8'))); } catch(e) { console.error('Order processing failed',e); }
});
app.use(express.json());
app.listen(PORT,()=>console.log(`Academia Arcana generator listening on :${PORT}`));
