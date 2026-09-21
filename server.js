const express = require("express");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const archiver = require("archiver");
const PDFDocument = require("pdfkit");
const nodemailer = require("nodemailer");

const app = express();

const PORT = process.env.PORT || 3000;

const BASE_URL = (process.env.BASE_URL || "").replace(/\/$/, "");

const SHOPIFY_SHOP_DOMAIN = process.env.SHOPIFY_SHOP_DOMAIN;
const SHOPIFY_CLIENT_ID = process.env.SHOPIFY_CLIENT_ID;

const SHOPIFY_CLIENT_SECRET =
  process.env.SHOPIFY_CLIENT_SECRET ||
  process.env.SHOPIFY_WEBHOOK_SECRET;

const SHOPIFY_WEBHOOK_SECRET =
  process.env.SHOPIFY_WEBHOOK_SECRET ||
  process.env.SHOPIFY_CLIENT_SECRET;

const DOWNLOAD_TOKEN_SECRET =
  process.env.DOWNLOAD_TOKEN_SECRET || "change-me";

const ARCANA_TEST_SECRET = process.env.ARCANA_TEST_SECRET;

const SHOPIFY_API_VERSION = "2026-07";

const WEBHOOK_URL = `${BASE_URL}/webhooks/orders-paid`;

const STORAGE_DIR = path.join(process.cwd(), "storage");

if (!fs.existsSync(STORAGE_DIR)) {
  fs.mkdirSync(STORAGE_DIR, { recursive: true });
}

/* =========================================================
   MAISONS
========================================================= */

const HOUSES = {
  IGNIS: {
    name: "IGNIS",
    emoji: "🔥",
    element: "Feu",
    animal: "Phénix",
    description:
      "Courage, passion, ambition et détermination."
  },

  NOCTIS: {
    name: "NOCTIS",
    emoji: "🌙",
    element: "Ombre",
    animal: "Corbeau",
    description:
      "Intuition, mystère, stratégie et observation."
  },

  SYLVA: {
    name: "SYLVA",
    emoji: "🌿",
    element: "Nature",
    animal: "Cerf",
    description:
      "Harmonie, patience, sagesse et équilibre."
  },

  AETHER: {
    name: "AETHER",
    emoji: "⚡",
    element: "Aether",
    animal: "Faucon",
    description:
      "Curiosité, créativité, découverte et liberté."
  }
};

/* =========================================================
   HELPERS
========================================================= */

function clean(value) {
  return String(value || "").trim();
}

function normalizeHouse(value) {
  const house = clean(value).toUpperCase();

  if (HOUSES[house]) {
    return house;
  }

  return "IGNIS";
}

function getLineProperty(lineItem, propertyName) {
  const properties = lineItem?.properties;

  if (!properties) {
    return "";
  }

  if (Array.isArray(properties)) {
    const found = properties.find(
      (item) =>
        item &&
        (item.name === propertyName ||
          item.key === propertyName)
    );

    return found ? clean(found.value) : "";
  }

  if (typeof properties === "object") {
    return clean(properties[propertyName]);
  }

  return "";
}

function getCustomerFirstName(order) {
  return clean(
    order?.customer?.first_name ||
      order?.customer?.firstName ||
      order?.billing_address?.first_name ||
      order?.shipping_address?.first_name ||
      order?.first_name
  );
}

function getCustomerLastName(order) {
  return clean(
    order?.customer?.last_name ||
      order?.customer?.lastName ||
      order?.billing_address?.last_name ||
      order?.shipping_address?.last_name ||
      order?.last_name
  );
}

/* =========================================================
   DOWNLOAD TOKEN
========================================================= */

function createDownloadToken(orderId) {
  return crypto
    .createHmac("sha256", DOWNLOAD_TOKEN_SECRET)
    .update(String(orderId))
    .digest("hex");
}

function verifyDownloadToken(orderId, token) {
  const expected = createDownloadToken(orderId);

  if (!token || token.length !== expected.length) {
    return false;
  }

  return crypto.timingSafeEqual(
    Buffer.from(expected),
    Buffer.from(token)
  );
}

/* =========================================================
   SHOPIFY HMAC
========================================================= */

function verifyShopifyHmac(rawBody, hmacHeader) {
  if (!rawBody || !hmacHeader || !SHOPIFY_WEBHOOK_SECRET) {
    return false;
  }

  const digest = crypto
    .createHmac("sha256", SHOPIFY_WEBHOOK_SECRET)
    .update(rawBody)
    .digest("base64");

  const provided = Buffer.from(hmacHeader, "utf8");
  const calculated = Buffer.from(digest, "utf8");

  if (provided.length !== calculated.length) {
    return false;
  }

  return crypto.timingSafeEqual(provided, calculated);
}

/* =========================================================
   SHOPIFY CLIENT CREDENTIALS
========================================================= */

let shopifyTokenCache = null;

function normalizeShopDomain(domain) {
  let shop = clean(domain);

  shop = shop
    .replace(/^https?:\/\//i, "")
    .replace(/\/.*$/, "");

  if (!shop.endsWith(".myshopify.com")) {
    shop = `${shop}.myshopify.com`;
  }

  return shop;
}

async function getShopifyAccessToken() {
  if (
    shopifyTokenCache &&
    shopifyTokenCache.expiresAt > Date.now() + 60_000
  ) {
    return shopifyTokenCache.token;
  }

  if (!SHOPIFY_SHOP_DOMAIN) {
    throw new Error("SHOPIFY_SHOP_DOMAIN manquant.");
  }

  if (!SHOPIFY_CLIENT_ID) {
    throw new Error("SHOPIFY_CLIENT_ID manquant.");
  }

  if (!SHOPIFY_CLIENT_SECRET) {
    throw new Error(
      "SHOPIFY_CLIENT_SECRET ou SHOPIFY_WEBHOOK_SECRET manquant."
    );
  }

  const shop = normalizeShopDomain(SHOPIFY_SHOP_DOMAIN);

  console.log("🔐 Demande de token Shopify...");

  const response = await fetch(
    `https://${shop}/admin/oauth/access_token`,
    {
      method: "POST",
      headers: {
        "Content-Type":
          "application/x-www-form-urlencoded"
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
    console.error("❌ Réponse Shopify token :", data);

    throw new Error(
      `Impossible d'obtenir le token Shopify (${response.status}).`
    );
  }

  shopifyTokenCache = {
    token: data.access_token,
    expiresAt:
      Date.now() +
      Number(data.expires_in || 86399) * 1000
  };

  console.log("✅ Token Shopify obtenu.");

  return data.access_token;
}

/* =========================================================
   SHOPIFY GRAPHQL
========================================================= */

async function shopifyGraphQL(query, variables = {}) {
  const token = await getShopifyAccessToken();

  const shop = normalizeShopDomain(SHOPIFY_SHOP_DOMAIN);

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
    console.error("❌ Shopify GraphQL HTTP :", response.status);
    console.error(data);

    throw new Error(
      `Shopify GraphQL HTTP ${response.status}`
    );
  }

  if (data.errors?.length) {
    console.error(
      "❌ Shopify GraphQL errors :",
      JSON.stringify(data.errors)
    );

    throw new Error(
      data.errors
        .map((error) => error.message)
        .join(" | ")
    );
  }

  return data;
}

/* =========================================================
   WEBHOOK ORDERS/PAID
========================================================= */

async function ensureOrdersPaidWebhook() {
  console.log("🔎 Vérification du webhook orders/paid...");

  if (!BASE_URL) {
    throw new Error("BASE_URL manquant.");
  }

  const query = `
    query {
      webhookSubscriptions(first: 50) {
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

  const result = await shopifyGraphQL(query);

  const subscriptions =
    result?.data?.webhookSubscriptions?.edges || [];

  const existing = subscriptions.find(
    (edge) =>
      edge?.node?.topic === "ORDERS_PAID"
  );

  if (existing) {
    console.log(
      `✅ Webhook orders/paid déjà présent : ${existing.node.id}`
    );

    console.log(
      `   URL : ${existing.node.uri || "non renseignée"}`
    );

    return existing.node;
  }

  console.log(
    "⚠️ Aucun webhook orders/paid trouvé. Création..."
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

  const resultCreate = await shopifyGraphQL(
    mutation,
    {
      topic: "ORDERS_PAID",
      webhookSubscription: {
        uri: WEBHOOK_URL
      }
    }
  );

  const payload =
    resultCreate?.data?.webhookSubscriptionCreate;

  if (payload?.userErrors?.length) {
    console.error(
      "❌ Erreurs création webhook :",
      payload.userErrors
    );

    throw new Error(
      payload.userErrors
        .map((error) => error.message)
        .join(" | ")
    );
  }

  if (!payload?.webhookSubscription) {
    throw new Error(
      "Shopify n'a pas retourné le webhook créé."
    );
  }

  console.log(
    `✅ Webhook orders/paid créé : ${payload.webhookSubscription.id}`
  );

  return payload.webhookSubscription;
}

/* =========================================================
   PDF
========================================================= */

function createPdf({
  type,
  firstName,
  lastName,
  houseKey,
  outputPath
}) {
  return new Promise((resolve, reject) => {
    const house =
      HOUSES[normalizeHouse(houseKey)];

    const doc = new PDFDocument({
      size: "A4",
      margin: 55
    });

    const stream =
      fs.createWriteStream(outputPath);

    stream.on("finish", resolve);
    stream.on("error", reject);

    doc.pipe(stream);

    const fullName =
      `${firstName} ${lastName}`.trim();

    /* HEADER */

    doc
      .fontSize(30)
      .fillColor("#17121f")
      .text("ACADEMIA ARCANA", {
        align: "center"
      });

    doc.moveDown(0.4);

    doc
      .fontSize(12)
      .fillColor("#806b99")
      .text("École des Arts Magiques", {
        align: "center"
      });

    doc.moveDown(2);

    /* TITLE */

    let title = "DOCUMENT ARCANA";

    if (type === "letter") {
      title = "LETTRE D'ADMISSION";
    }

    if (type === "certificate") {
      title = "CERTIFICAT D'APPARTENANCE";
    }

    if (type === "profile") {
      title = "PROFIL ARCANA";
    }

    if (type === "passport") {
      title = "PASSEPORT MAGIQUE";
    }

    doc
      .fontSize(24)
      .fillColor("#24172e")
      .text(title, {
        align: "center"
      });

    doc.moveDown(2);

    /* NAME */

    doc
      .fontSize(18)
      .fillColor("#17121f")
      .text(fullName || "Apprenti Arcana", {
        align: "center"
      });

    doc.moveDown(1.5);

    /* HOUSE */

    doc
      .fontSize(28)
      .fillColor("#6b4b83")
      .text(
        `${house.emoji} ${house.name}`,
        {
          align: "center"
        }
      );

    doc.moveDown(0.7);

    doc
      .fontSize(12)
      .fillColor("#555")
      .text(
        `Élément : ${house.element}`,
        {
          align: "center"
        }
      );

    doc.text(
      `Animal : ${house.animal}`,
      {
        align: "center"
      }
    );

    doc.moveDown(2);

    /* TEXT */

    if (type === "letter") {
      doc
        .fontSize(13)
        .fillColor("#333")
        .text(
          `Cher ${firstName || "apprenti"},`
        );

      doc.moveDown(1);

      doc.text(
        `Nous avons le plaisir de vous annoncer votre admission à Academia Arcana. Votre parcours magique commence aujourd'hui.`
      );

      doc.moveDown(1);

      doc.text(
        `Votre maison, ${house.name}, vous ouvre désormais ses portes. Elle représente ${house.description.toLowerCase()}`
      );

      doc.moveDown(1);

      doc.text(
        `Gardez précieusement cette lettre. Elle marque le commencement d'une nouvelle aventure.`
      );
    }

    if (type === "certificate") {
      doc
        .fontSize(13)
        .text(
          `Le présent certificat atteste que ${fullName || "l'apprenti"} appartient à la maison ${house.name} de l'Academia Arcana.`
        );
    }

    if (type === "profile") {
      doc
        .fontSize(13)
        .text(
          `Profil magique de ${fullName || "l'apprenti"}.`
        );

      doc.moveDown(1);

      doc.text(
        `Maison : ${house.name}`
      );

      doc.text(
        `Élément : ${house.element}`
      );

      doc.text(
        `Animal : ${house.animal}`
      );

      doc.moveDown(1);

      doc.text(
        `Traits : ${house.description}`
      );
    }

    if (type === "passport") {
      doc
        .fontSize(13)
        .text(
          `Passeport magique attribué à ${fullName || "l'apprenti"}.`
        );

      doc.moveDown(1);

      doc.text(
        `Maison : ${house.name}`
      );

      doc.text(
        `Élément : ${house.element}`
      );

      doc.text(
        `Animal : ${house.animal}`
      );
    }

    doc.moveDown(3);

    doc
      .fontSize(10)
      .fillColor("#777")
      .text(
        "Academia Arcana — Univers fantastique original",
        {
          align: "center"
        }
      );

    doc.end();
  });
}

/* =========================================================
   DETECTION TYPE PRODUIT
========================================================= */

function getDocumentType(productTitle) {
  const title = clean(productTitle).toLowerCase();

  if (
    title.includes("lettre") ||
    title.includes("admission")
  ) {
    return "letter";
  }

  if (
    title.includes("certificat") ||
    title.includes("appartenance")
  ) {
    return "certificate";
  }

  if (
    title.includes("profil") ||
    title.includes("arcana")
  ) {
    return "profile";
  }

  if (
    title.includes("passeport") ||
    title.includes("passport")
  ) {
    return "passport";
  }

  return "letter";
}

/* =========================================================
   GENERATION COMMANDE
========================================================= */

async function processOrder(order) {
  const orderId = String(
    order?.id || `ARCANA-${Date.now()}`
  );

  const firstName =
    getCustomerFirstName(order) ||
    "Apprenti";

  const lastName =
    getCustomerLastName(order);

  const lineItems =
    Array.isArray(order?.line_items)
      ? order.line_items
      : [];

  const personalizedItems =
    lineItems.filter((item) => {
      const flag = getLineProperty(
        item,
        "_arcana_personalized"
      );

      return flag.toLowerCase() === "true";
    });

  if (!personalizedItems.length) {
    console.log(
      `ℹ️ Aucune ligne personnalisée pour la commande ${orderId}.`
    );

    return {
      generated: false,
      reason: "no_personalized_items"
    };
  }

  const orderDir = path.join(
    STORAGE_DIR,
    orderId.replace(/[^a-zA-Z0-9_-]/g, "_")
  );

  fs.mkdirSync(orderDir, {
    recursive: true
  });

  const generatedFiles = [];

  for (const item of personalizedItems) {
    const itemFirstName =
      getLineProperty(item, "Prénom") ||
      firstName;

    const itemLastName =
      getLineProperty(item, "Nom") ||
      lastName;

    const house =
      normalizeHouse(
        getLineProperty(item, "Maison")
      );

    const type =
      getDocumentType(item.title);

    const safeTitle =
      clean(item.title)
        .replace(/[^a-zA-Z0-9À-ÿ_-]+/g, "_")
        .slice(0, 80) ||
      "document";

    const filename =
      `${safeTitle}_${itemFirstName}_${itemLastName}.pdf`
        .replace(/[^a-zA-Z0-9À-ÿ_.-]/g, "_");

    const pdfPath =
      path.join(orderDir, filename);

    console.log(
      `📄 Génération : ${filename}`
    );

    await createPdf({
      type,
      firstName: itemFirstName,
      lastName: itemLastName,
      houseKey: house,
      outputPath: pdfPath
    });

    generatedFiles.push({
      path: pdfPath,
      filename
    });
  }

  const zipFilename =
    `academia-arcana-${orderId}.zip`;

  const zipPath =
    path.join(STORAGE_DIR, zipFilename);

  await new Promise((resolve, reject) => {
    const output =
      fs.createWriteStream(zipPath);

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

    for (const file of generatedFiles) {
      archive.file(file.path, {
        name: file.filename
      });
    }

    archive.finalize();
  });

  const token =
    createDownloadToken(orderId);

  const downloadUrl =
    `${BASE_URL}/download/${encodeURIComponent(
      orderId
    )}/${token}`;

  console.log(
    `📦 ZIP généré : ${zipFilename}`
  );

  console.log(
    `🔗 ${downloadUrl}`
  );

  /* EMAIL OPTIONNEL */

  if (
    process.env.SMTP_HOST &&
    process.env.SMTP_USER &&
    process.env.SMTP_PASS &&
    order?.email
  ) {
    try {
      const transporter =
        nodemailer.createTransport({
          host: process.env.SMTP_HOST,
          port:
            Number(process.env.SMTP_PORT) ||
            587,
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

      await transporter.sendMail({
        from:
          process.env.SMTP_FROM ||
          process.env.SMTP_USER,

        to: order.email,

        subject:
          "✨ Votre document Academia Arcana",

        text:
          `Votre document personnalisé est prêt.\n\n${downloadUrl}`
      });

      console.log(
        `📧 Email envoyé à ${order.email}`
      );
    } catch (emailError) {
      console.error(
        "⚠️ Erreur email :",
        emailError.message
      );
    }
  }

  return {
    generated: true,
    orderId,
    firstName,
    lastName,
    house:
      normalizeHouse(
        getLineProperty(
          personalizedItems[0],
          "Maison"
        )
      ),
    files:
      generatedFiles.map(
        (file) => file.filename
      ),
    zipFilename,
    downloadUrl
  };
}

/* =========================================================
   ROOT
========================================================= */

app.get("/", (req, res) => {
  res.status(200).send(`
    <!doctype html>
    <html lang="fr">
      <head>
        <meta charset="utf-8">
        <title>Academia Arcana</title>
        <style>
          body {
            margin: 0;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            background: #09070d;
            color: white;
            font-family: Arial, sans-serif;
            text-align: center;
          }

          .box {
            padding: 40px;
          }

          h1 {
            font-size: 38px;
            margin-bottom: 10px;
          }

          p {
            color: #b8adbf;
          }
        </style>
      </head>

      <body>
        <div class="box">
          <h1>✦ Academia Arcana</h1>
          <p>Générateur de documents personnalisés</p>
          <p>✓ Service opérationnel</p>
        </div>
      </body>
    </html>
  `);
});

/* =========================================================
   HEALTH
========================================================= */

app.get("/health", (req, res) => {
  res.json({
    ok: true,
    service: "academia-arcana-generator"
  });
});

/* =========================================================
   WEBHOOK SHOPIFY
   IMPORTANT : raw body pour vérifier le HMAC
========================================================= */

app.post(
  "/webhooks/orders-paid",
  express.raw({
    type: "application/json"
  }),
  async (req, res) => {
    try {
      const hmac =
        req.get(
          "X-Shopify-Hmac-Sha256"
        );

      const webhookId =
        req.get(
          "X-Shopify-Webhook-Id"
        );

      console.log(
        `📥 Webhook orders/paid reçu${
          webhookId
            ? ` (${webhookId})`
            : ""
        }`
      );

      if (
        !verifyShopifyHmac(
          req.body,
          hmac
        )
      ) {
        console.error(
          "❌ HMAC Shopify invalide."
        );

        return res
          .status(401)
          .send("Invalid HMAC");
      }

      let order;

      try {
        order =
          JSON.parse(
            req.body.toString("utf8")
          );
      } catch (error) {
        console.error(
          "❌ JSON webhook invalide."
        );

        return res
          .status(400)
          .send("Invalid JSON");
      }

      /* Réponse rapide à Shopify */

      res.status(200).send("OK");

      /* Traitement après réponse */

      try {
        const result =
          await processOrder(order);

        console.log(
          "✅ Commande traitée :",
          JSON.stringify(result)
        );
      } catch (error) {
        console.error(
          "❌ Erreur traitement commande :",
          error
        );
      }
    } catch (error) {
      console.error(
        "❌ Erreur webhook :",
        error
      );

      if (!res.headersSent) {
        res
          .status(500)
          .send("Webhook error");
      }
    }
  }
);

/* =========================================================
   JSON POUR LES AUTRES ROUTES
========================================================= */

app.use(express.json());

/* =========================================================
   TEST INTERNE
========================================================= */

app.post(
  "/test/generate",
  async (req, res) => {
    try {
      if (!ARCANA_TEST_SECRET) {
        return res.status(503).json({
          ok: false,
          error:
            "ARCANA_TEST_SECRET n'est pas configuré sur Render."
        });
      }

      const providedSecret =
        req.get(
          "X-Arcana-Test-Secret"
        );

      if (
        !providedSecret ||
        providedSecret !== ARCANA_TEST_SECRET
      ) {
        return res.status(401).json({
          ok: false,
          error: "Secret de test invalide."
        });
      }

      const testOrder = {
        id:
          `TEST-ARCANA-${Date.now()}`,

        first_name:
          "Mathis",

        last_name:
          "BRISARD",

        email:
          "",

        line_items: [
          {
            title:
              "Lettre d'admission – Academia Arcana",

            quantity: 1,

            properties: {
              _arcana_personalized:
                "true",

              Prénom:
                "Mathis",

              Nom:
                "BRISARD",

              Maison:
                "IGNIS"
            }
          }
        ]
      };

      console.log(
        "🧪 Génération de test demandée."
      );

      const result =
        await processOrder(testOrder);

      return res.json({
        ok: true,
        test: true,
        ...result
      });
    } catch (error) {
      console.error(
        "❌ Erreur test :",
        error
      );

      return res.status(500).json({
        ok: false,
        error:
          error.message ||
          "Erreur inconnue."
      });
    }
  }
);

/* =========================================================
   DOWNLOAD
========================================================= */

app.get(
  "/download/:order/:token",
  (req, res) => {
    try {
      const orderId =
        req.params.order;

      const token =
        req.params.token;

      if (
        !verifyDownloadToken(
          orderId,
          token
        )
      ) {
        return res
          .status(403)
          .send("Lien de téléchargement invalide.");
      }

      const zipFilename =
        `academia-arcana-${orderId}.zip`;

      const zipPath =
        path.join(
          STORAGE_DIR,
          zipFilename
        );

      if (!fs.existsSync(zipPath)) {
        return res
          .status(404)
          .send(
            "Le fichier n'est plus disponible."
          );
      }

      return res.download(
        zipPath,
        zipFilename
      );
    } catch (error) {
      console.error(
        "❌ Erreur téléchargement :",
        error
      );

      return res
        .status(500)
        .send(
          "Erreur de téléchargement."
        );
    }
  }
);

/* =========================================================
   404
========================================================= */

app.use((req, res) => {
  res.status(404).json({
    ok: false,
    error: "Route introuvable."
  });
});

/* =========================================================
   START
========================================================= */

app.listen(PORT, () => {
  console.log(
    `Academia Arcana generator listening on :${PORT}`
  );

  console.log(
    "🔎 Vérification du webhook orders/paid..."
  );

  setTimeout(async () => {
    try {
      await ensureOrdersPaidWebhook();

      console.log(
        "✅ Vérification Shopify terminée."
      );
    } catch (error) {
      console.error(
        "❌ Vérification Shopify échouée :",
        error.message
      );
    }
  }, 1000);
});
