import express from "express";
import crypto from "crypto";
import fs from "fs";
import path from "path";
import archiver from "archiver";
import PDFDocument from "pdfkit";
import nodemailer from "nodemailer";

const app = express();

const PORT = process.env.PORT || 3000;
const BASE_URL = (process.env.BASE_URL || "").replace(/\/$/, "");

const SHOPIFY_SHOP_DOMAIN = process.env.SHOPIFY_SHOP_DOMAIN;
const SHOPIFY_CLIENT_ID = process.env.SHOPIFY_CLIENT_ID;

// Le même secret Shopify sert à l'authentification API
// et à la vérification HMAC des webhooks.
const SHOPIFY_CLIENT_SECRET =
  process.env.SHOPIFY_CLIENT_SECRET ||
  process.env.SHOPIFY_WEBHOOK_SECRET;

const SHOPIFY_WEBHOOK_SECRET =
  process.env.SHOPIFY_WEBHOOK_SECRET ||
  process.env.SHOPIFY_CLIENT_SECRET;

const DOWNLOAD_TOKEN_SECRET =
  process.env.DOWNLOAD_TOKEN_SECRET || "change-me";

const SHOPIFY_API_VERSION = "2026-07";

const WEBHOOK_URL =
  `${BASE_URL}/webhooks/orders-paid`;

const STORAGE_DIR = path.join(process.cwd(), "storage");

if (!fs.existsSync(STORAGE_DIR)) {
  fs.mkdirSync(STORAGE_DIR, { recursive: true });
}

const processedWebhookIds = new Set();

const HOUSES = {
  IGNIS: {
    emoji: "🔥",
    element: "Feu",
    animal: "Phénix",
    description: "Courage, passion et ambition."
  },
  NOCTIS: {
    emoji: "🌙",
    element: "Ombre",
    animal: "Corbeau",
    description: "Intuition, mystère et stratégie."
  },
  SYLVA: {
    emoji: "🌿",
    element: "Nature",
    animal: "Cerf",
    description: "Harmonie, patience et sagesse."
  },
  AETHER: {
    emoji: "⚡",
    element: "Aether",
    animal: "Faucon",
    description: "Curiosité, créativité et découverte."
  }
};

/* =========================================================
   UTILITAIRES
========================================================= */

function clean(value) {
  return String(value || "").trim();
}

function normalizeHouse(value) {
  const house = clean(value).toUpperCase();

  return HOUSES[house] ? house : "AETHER";
}

function getLineProperty(lineItem, name) {
  const properties = lineItem?.properties || lineItem?.custom_attributes || [];

  const property = properties.find(
    (item) =>
      item?.name === name ||
      item?.key === name
  );

  return property?.value ?? "";
}

function createDownloadToken(orderId) {
  return crypto
    .createHmac("sha256", DOWNLOAD_TOKEN_SECRET)
    .update(String(orderId))
    .digest("hex");
}

function verifyDownloadToken(orderId, token) {
  const expected = createDownloadToken(orderId);

  try {
    return crypto.timingSafeEqual(
      Buffer.from(expected),
      Buffer.from(String(token))
    );
  } catch {
    return false;
  }
}

function verifyShopifyHmac(rawBody, hmacHeader) {
  if (!hmacHeader || !SHOPIFY_WEBHOOK_SECRET) {
    return false;
  }

  const digest = crypto
    .createHmac("sha256", SHOPIFY_WEBHOOK_SECRET)
    .update(rawBody)
    .digest("base64");

  try {
    return crypto.timingSafeEqual(
      Buffer.from(digest),
      Buffer.from(hmacHeader)
    );
  } catch {
    return false;
  }
}

/* =========================================================
   SHOPIFY AUTHENTICATION
========================================================= */

function getShopifyDomain() {
  if (!SHOPIFY_SHOP_DOMAIN) {
    throw new Error("SHOPIFY_SHOP_DOMAIN manquant.");
  }

  let domain = SHOPIFY_SHOP_DOMAIN
    .trim()
    .replace(/^https?:\/\//, "")
    .replace(/\/$/, "");

  if (!domain.endsWith(".myshopify.com")) {
    domain += ".myshopify.com";
  }

  return domain;
}

let cachedAccessToken = null;
let cachedTokenExpiresAt = 0;

async function getShopifyAccessToken() {
  if (
    cachedAccessToken &&
    Date.now() < cachedTokenExpiresAt - 5 * 60 * 1000
  ) {
    return cachedAccessToken;
  }

  if (!SHOPIFY_CLIENT_ID) {
    throw new Error("SHOPIFY_CLIENT_ID manquant.");
  }

  if (!SHOPIFY_CLIENT_SECRET) {
    throw new Error(
      "SHOPIFY_CLIENT_SECRET / SHOPIFY_WEBHOOK_SECRET manquant."
    );
  }

  const shop = getShopifyDomain();

  const response = await fetch(
    `https://${shop}/admin/oauth/access_token`,
    {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded"
      },
      body: new URLSearchParams({
        grant_type: "client_credentials",
        client_id: SHOPIFY_CLIENT_ID,
        client_secret: SHOPIFY_CLIENT_SECRET
      })
    }
  );

  const data = await response.json();

  if (!response.ok || !data.access_token) {
    throw new Error(
      `Shopify token error: ${JSON.stringify(data)}`
    );
  }

  cachedAccessToken = data.access_token;

  const expiresIn =
    Number(data.expires_in) || 86399;

  cachedTokenExpiresAt =
    Date.now() + expiresIn * 1000;

  console.log("✅ Token Shopify obtenu.");

  return cachedAccessToken;
}

async function shopifyGraphQL(query, variables = {}) {
  const token = await getShopifyAccessToken();
  const shop = getShopifyDomain();

  const response = await fetch(
    `https://${shop}/admin/api/${SHOPIFY_API_VERSION}/graphql.json`,
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Shopify-Access-Token": token
      },
      body: JSON.stringify({
        query,
        variables
      })
    }
  );

  const data = await response.json();

  if (!response.ok) {
    throw new Error(
      `Shopify GraphQL HTTP error: ${JSON.stringify(data)}`
    );
  }

  if (data.errors?.length) {
    throw new Error(
      `Shopify GraphQL error: ${JSON.stringify(data.errors)}`
    );
  }

  return data.data;
}

/* =========================================================
   WEBHOOK SHOPIFY
========================================================= */

async function ensureOrdersPaidWebhook() {
  console.log("🔎 Vérification du webhook orders/paid...");

  const query = `
    query {
      webhookSubscriptions(
        first: 50,
        topics: [ORDERS_PAID]
      ) {
        edges {
          node {
            id
            topic
            uri
          }
        }
      }
    }
  `;

  const data = await shopifyGraphQL(query);

  const subscriptions =
    data?.webhookSubscriptions?.edges?.map(
      (edge) => edge.node
    ) || [];

  const existing = subscriptions.find(
    (subscription) =>
      subscription.uri === WEBHOOK_URL
  );

  if (existing) {
    console.log(
      `✅ Webhook orders/paid déjà présent : ${existing.id}`
    );

    return existing;
  }

  console.log(
    `➕ Création du webhook : ${WEBHOOK_URL}`
  );

  const mutation = `
    mutation webhookSubscriptionCreate(
      $topic: WebhookSubscriptionTopic!,
      $webhookSubscription: WebhookSubscriptionInput!
    ) {
      webhookSubscriptionCreate(
        topic: $topic,
        webhookSubscription: $webhookSubscription
      ) {
        webhookSubscription {
          id
          topic
          uri
        }
        userErrors {
          field
          message
        }
      }
    }
  `;

  const dataCreated = await shopifyGraphQL(
    mutation,
    {
      topic: "ORDERS_PAID",
      webhookSubscription: {
        uri: WEBHOOK_URL
      }
    }
  );

  const result =
    dataCreated?.webhookSubscriptionCreate;

  if (result?.userErrors?.length) {
    throw new Error(
      `Erreur création webhook : ${JSON.stringify(
        result.userErrors
      )}`
    );
  }

  console.log(
    "✅ Webhook orders/paid créé :",
    result?.webhookSubscription
  );

  return result?.webhookSubscription;
}

/* =========================================================
   PDF
========================================================= */

function createPdf({
  outputPath,
  type,
  firstName,
  lastName,
  house
}) {
  return new Promise((resolve, reject) => {
    const doc = new PDFDocument({
      size: "A4",
      margin: 60
    });

    const stream =
      fs.createWriteStream(outputPath);

    stream.on("finish", resolve);
    stream.on("error", reject);

    doc.pipe(stream);

    const houseData = HOUSES[house];

    doc.fontSize(28)
      .text("ACADEMIA ARCANA", {
        align: "center"
      });

    doc.moveDown();

    doc.fontSize(16)
      .text("École des Arts Mystiques", {
        align: "center"
      });

    doc.moveDown(3);

    if (type === "letter") {
      doc.fontSize(24)
        .text("LETTRE D'ADMISSION", {
          align: "center"
        });

      doc.moveDown(2);

      doc.fontSize(16)
        .text(
          `Cher ${firstName} ${lastName},`,
          {
            align: "center"
          }
        );

      doc.moveDown();

      doc.fontSize(13).text(
        `Nous avons le plaisir de vous annoncer que votre candidature a été acceptée au sein de l'Academia Arcana.

Votre maison est : ${house}

${houseData.emoji} ${house}
Élément : ${houseData.element}
Animal : ${houseData.animal}

${houseData.description}

Votre aventure magique commence aujourd'hui.`
      );
    }

    else if (type === "certificate") {
      doc.fontSize(24)
        .text("CERTIFICAT D'APPARTENANCE", {
          align: "center"
        });

      doc.moveDown(3);

      doc.fontSize(18)
        .text(
          `${firstName} ${lastName}`,
          {
            align: "center"
          }
        );

      doc.moveDown();

      doc.fontSize(16)
        .text(
          `Maison ${house}`,
          {
            align: "center"
          }
        );

      doc.moveDown();

      doc.fontSize(13)
        .text(
          `${houseData.emoji} ${houseData.description}`,
          {
            align: "center"
          }
        );
    }

    else if (type === "profile") {
      doc.fontSize(24)
        .text("PROFIL ARCANA", {
          align: "center"
        });

      doc.moveDown(2);

      doc.fontSize(15)
        .text(`Prénom : ${firstName}`);

      doc.text(`Nom : ${lastName}`);

      doc.text(`Maison : ${house}`);

      doc.text(`Élément : ${houseData.element}`);

      doc.text(`Animal : ${houseData.animal}`);

      doc.moveDown();

      doc.fontSize(13)
        .text(houseData.description);
    }

    else {
      doc.fontSize(24)
        .text("PASSEPORT ARCANA", {
          align: "center"
        });

      doc.moveDown(2);

      doc.fontSize(16)
        .text(`${firstName} ${lastName}`, {
          align: "center"
        });

      doc.moveDown();

      doc.fontSize(15)
        .text(`Maison : ${house}`, {
          align: "center"
        });

      doc.moveDown();

      doc.fontSize(13)
        .text(
          `${houseData.emoji} ${houseData.element} • ${houseData.animal}`,
          {
            align: "center"
          }
        );
    }

    doc.moveDown(5);

    doc.fontSize(10)
      .text(
        "Academia Arcana — Document numérique personnalisé",
        {
          align: "center"
        }
      );

    doc.end();
  });
}

/* =========================================================
   TRAITEMENT COMMANDE
========================================================= */

async function processOrder(order) {
  const orderId = order.id;

  console.log(
    `📦 Traitement de la commande ${orderId}`
  );

  const lineItems = order.line_items || [];

  const personalizedItems =
    lineItems.filter((item) => {
      const personalized =
        getLineProperty(
          item,
          "_arcana_personalized"
        );

      return String(personalized).toLowerCase() === "true";
    });

  if (!personalizedItems.length) {
    console.log(
      `ℹ️ Commande ${orderId} sans produit personnalisé.`
    );

    return;
  }

  const firstItem =
    personalizedItems[0];

  const firstName =
    clean(
      getLineProperty(firstItem, "Prénom")
    ) ||
    clean(order.customer?.first_name) ||
    clean(order.billing_address?.first_name) ||
    "Apprenti";

  const lastName =
    clean(
      getLineProperty(firstItem, "Nom")
    ) ||
    clean(order.customer?.last_name) ||
    clean(order.billing_address?.last_name) ||
    "Arcana";

  const house =
    normalizeHouse(
      getLineProperty(firstItem, "Maison")
    );

  const orderDir =
    path.join(
      STORAGE_DIR,
      String(orderId)
    );

  fs.mkdirSync(orderDir, {
    recursive: true
  });

  const generatedFiles = [];

  for (const item of personalizedItems) {
    const title =
      clean(item.title).toLowerCase();

    let type = "passport";

    if (title.includes("lettre")) {
      type = "letter";
    }

    if (
      title.includes("certificat")
    ) {
      type = "certificate";
    }

    if (
      title.includes("profil")
    ) {
      type = "profile";
    }

    const safeType =
      type === "letter"
        ? "lettre-admission"
        : type === "certificate"
        ? "certificat"
        : type === "profile"
        ? "profil-arcana"
        : "passeport-arcana";

    const pdfPath =
      path.join(
        orderDir,
        `${safeType}.pdf`
      );

    await createPdf({
      outputPath: pdfPath,
      type,
      firstName,
      lastName,
      house
    });

    generatedFiles.push(pdfPath);
  }

  const zipPath =
    path.join(
      STORAGE_DIR,
      `academia-arcana-${orderId}.zip`
    );

  await createZip(
    generatedFiles,
    zipPath
  );

  const token =
    createDownloadToken(orderId);

  const downloadUrl =
    `${BASE_URL}/download/${encodeURIComponent(
      orderId
    )}/${token}`;

  console.log(
    `✅ ZIP généré pour ${firstName} ${lastName}`
  );

  console.log(
    `🔗 ${downloadUrl}`
  );

  await sendEmailIfConfigured({
    order,
    firstName,
    lastName,
    house,
    downloadUrl
  });
}

/* =========================================================
   ZIP
========================================================= */

function createZip(files, outputPath) {
  return new Promise((resolve, reject) => {
    const output =
      fs.createWriteStream(outputPath);

    const archive =
      archiver("zip", {
        zlib: {
          level: 9
        }
      });

    output.on("close", resolve);
    output.on("error", reject);

    archive.on("error", reject);

    archive.pipe(output);

    for (const file of files) {
      archive.file(
        file,
        {
          name: path.basename(file)
        }
      );
    }

    archive.finalize();
  });
}

/* =========================================================
   EMAIL
========================================================= */

async function sendEmailIfConfigured({
  order,
  firstName,
  lastName,
  house,
  downloadUrl
}) {
  if (
    !process.env.SMTP_HOST ||
    !process.env.SMTP_USER ||
    !process.env.SMTP_PASS
  ) {
    console.log(
      "ℹ️ SMTP non configuré : aucun email envoyé."
    );

    return;
  }

  const transporter =
    nodemailer.createTransport({
      host: process.env.SMTP_HOST,
      port:
        Number(
          process.env.SMTP_PORT || 587
        ),
      secure:
        String(
          process.env.SMTP_SECURE
        ).toLowerCase() === "true",
      auth: {
        user:
          process.env.SMTP_USER,
        pass:
          process.env.SMTP_PASS
      }
    });

  const email =
    order.email ||
    order.customer?.email;

  if (!email) {
    console.log(
      "⚠️ Aucun email client trouvé."
    );

    return;
  }

  await transporter.sendMail({
    from:
      process.env.MAIL_FROM ||
      process.env.SMTP_USER,
    to: email,
    subject:
      "✨ Votre aventure Academia Arcana commence",
    text:
      `Bonjour ${firstName} ${lastName},

Votre commande Academia Arcana est prête.

Maison : ${house}

Téléchargez vos documents personnalisés ici :

${downloadUrl}

À bientôt à l'Academia Arcana ✨`,
    html: `
      <h2>✨ Academia Arcana</h2>

      <p>
        Bonjour <strong>${firstName} ${lastName}</strong>,
      </p>

      <p>
        Votre commande personnalisée est prête.
      </p>

      <p>
        <strong>Maison : ${house}</strong>
      </p>

      <p>
        <a href="${downloadUrl}">
          Télécharger mes documents
        </a>
      </p>

      <p>
        Votre aventure commence maintenant. ✨
      </p>
    `
  });

  console.log(
    `📧 Email envoyé à ${email}`
  );
}

/* =========================================================
   ROUTES
========================================================= */

// Page d'accueil
app.get("/", (req, res) => {
  res.status(200).send(`
    <!DOCTYPE html>
    <html lang="fr">
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width,initial-scale=1">
        <title>Academia Arcana Generator</title>
        <style>
          body {
            margin: 0;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            background: #09070d;
            color: #eee;
            font-family: Arial, sans-serif;
            text-align: center;
          }

          .box {
            max-width: 650px;
            padding: 50px;
          }

          h1 {
            font-size: 42px;
            margin-bottom: 10px;
          }

          p {
            color: #aaa;
          }

          .status {
            margin-top: 30px;
            padding: 15px;
            border: 1px solid #333;
            border-radius: 10px;
          }
        </style>
      </head>

      <body>
        <div class="box">
          <h1>✦ Academia Arcana</h1>
          <p>Générateur de documents personnalisés</p>

          <div class="status">
            ✓ Service opérationnel
          </div>
        </div>
      </body>
    </html>
  `);
});

// Health check
app.get("/health", (req, res) => {
  res.json({
    ok: true,
    service: "academia-arcana-generator"
  });
});

/*
 * IMPORTANT :
 * Le webhook utilise express.raw()
 * pour vérifier le HMAC sur le corps brut.
 */
app.post(
  "/webhooks/orders-paid",
  express.raw({
    type: "application/json"
  }),
  async (req, res) => {
    const rawBody = req.body;

    const hmac =
      req.get(
        "X-Shopify-Hmac-SHA256"
      );

    if (
      !verifyShopifyHmac(
        rawBody,
        hmac
      )
    ) {
      console.warn(
        "❌ HMAC Shopify invalide."
      );

      return res
        .status(401)
        .send("Invalid HMAC");
    }

    const webhookId =
      req.get(
        "X-Shopify-Webhook-Id"
      );

    if (
      webhookId &&
      processedWebhookIds.has(webhookId)
    ) {
      console.log(
        `ℹ️ Webhook déjà traité : ${webhookId}`
      );

      return res
        .status(200)
        .send("Already processed");
    }

    if (webhookId) {
      processedWebhookIds.add(
        webhookId
      );
    }

    let order;

    try {
      order =
        JSON.parse(
          rawBody.toString("utf8")
        );
    } catch (error) {
      console.error(
        "❌ JSON invalide :",
        error
      );

      return res
        .status(400)
        .send("Invalid JSON");
    }

    /*
     * Shopify attend une réponse rapide.
     * On accuse réception puis on génère
     * le fichier en arrière-plan.
     */
    res
      .status(200)
      .send("OK");

    processOrder(order).catch(
      (error) => {
        console.error(
          "❌ Erreur traitement commande :",
          error
        );
      }
    );
  }
);

// Download sécurisé
app.get(
  "/download/:order/:token",
  (req, res) => {
    const {
      order,
      token
    } = req.params;

    if (
      !verifyDownloadToken(
        order,
        token
      )
    ) {
      return res
        .status(403)
        .send("Lien invalide.");
    }

    const zipPath =
      path.join(
        STORAGE_DIR,
        `academia-arcana-${order}.zip`
      );

    if (!fs.existsSync(zipPath)) {
      return res
        .status(404)
        .send(
          "Le fichier n'est plus disponible."
        );
    }

    res.download(
      zipPath,
      `academia-arcana-${order}.zip`
    );
  }
);

/* =========================================================
   START
========================================================= */

app.listen(PORT, () => {
  console.log(`Academia Arcana generator listening on :${PORT}`);

  setTimeout(async () => {
    console.log("🔎 Vérification du webhook orders/paid...");

    try {
      await ensureOrdersPaidWebhook();
      console.log("✅ Vérification Shopify terminée.");
    } catch (error) {
      console.error("❌ Erreur configuration Shopify :");
      console.error(error?.message || error);
    }
  }, 1500);
});
