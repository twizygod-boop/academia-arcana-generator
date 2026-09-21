const express = require("express");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const archiver = require("archiver");
const PDFDocument = require("pdfkit");
const nodemailer = require("nodemailer");

const app = express();

/* =========================================================
   CONFIGURATION
========================================================= */

const PORT = process.env.PORT || 3000;

const BASE_URL = (process.env.BASE_URL || "").replace(/\/$/, "");

const SHOPIFY_SHOP_DOMAIN =
  process.env.SHOPIFY_SHOP_DOMAIN;

const SHOPIFY_CLIENT_ID =
  process.env.SHOPIFY_CLIENT_ID;

const SHOPIFY_CLIENT_SECRET =
  process.env.SHOPIFY_CLIENT_SECRET ||
  process.env.SHOPIFY_WEBHOOK_SECRET;

const SHOPIFY_WEBHOOK_SECRET =
  process.env.SHOPIFY_WEBHOOK_SECRET ||
  process.env.SHOPIFY_CLIENT_SECRET;

const DOWNLOAD_TOKEN_SECRET =
  process.env.DOWNLOAD_TOKEN_SECRET ||
  "change-me";

const ARCANA_TEST_SECRET =
  process.env.ARCANA_TEST_SECRET;

const SHOPIFY_API_VERSION = "2026-07";

const WEBHOOK_URL =
  `${BASE_URL}/webhooks/orders-paid`;

const STORAGE_DIR =
  path.join(process.cwd(), "storage");

/* =========================================================
   DOSSIER STORAGE
========================================================= */

if (!fs.existsSync(STORAGE_DIR)) {
  fs.mkdirSync(STORAGE_DIR, {
    recursive: true
  });
}

/* =========================================================
   MAISONS ARCANA
========================================================= */

const HOUSES = {
  IGNIS: {
    name: "IGNIS",
    element: "Feu",
    animal: "Phenix",
    description:
      "courage, passion, ambition et determination"
  },

  NOCTIS: {
    name: "NOCTIS",
    element: "Ombre",
    animal: "Corbeau",
    description:
      "intuition, mystere, strategie et observation"
  },

  SYLVA: {
    name: "SYLVA",
    element: "Nature",
    animal: "Cerf",
    description:
      "harmonie, patience, sagesse et equilibre"
  },

  AETHER: {
    name: "AETHER",
    element: "Aether",
    animal: "Faucon",
    description:
      "curiosite, creativite, decouverte et liberte"
  }
};

/* =========================================================
   STYLE DES MAISONS
========================================================= */

const HOUSE_STYLES = {
  IGNIS: {
    primary: "#8E2F35",
    secondary: "#C99A3D",
    light: "#F6E8E4",
    symbol: "I"
  },

  NOCTIS: {
    primary: "#263A68",
    secondary: "#A9B7D6",
    light: "#E9EDF6",
    symbol: "N"
  },

  SYLVA: {
    primary: "#356B4B",
    secondary: "#A9C58C",
    light: "#E9F1E8",
    symbol: "S"
  },

  AETHER: {
    primary: "#60458C",
    secondary: "#B9A6D9",
    light: "#EEEAF5",
    symbol: "A"
  }
};

/* =========================================================
   HELPERS
========================================================= */

function clean(value) {
  return String(value || "").trim();
}

function normalizeHouse(value) {
  const house =
    clean(value).toUpperCase();

  if (HOUSES[house]) {
    return house;
  }

  return "IGNIS";
}

function getLineProperty(
  lineItem,
  propertyName
) {
  const properties =
    lineItem?.properties;

  if (!properties) {
    return "";
  }

  if (Array.isArray(properties)) {
    const found =
      properties.find(
        (item) =>
          item &&
          (
            item.name === propertyName ||
            item.key === propertyName
          )
      );

    return found
      ? clean(found.value)
      : "";
  }

  if (typeof properties === "object") {
    return clean(
      properties[propertyName]
    );
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
   TOKEN DE TELECHARGEMENT
========================================================= */

function createDownloadToken(orderId) {
  return crypto
    .createHmac(
      "sha256",
      DOWNLOAD_TOKEN_SECRET
    )
    .update(String(orderId))
    .digest("hex");
}

function verifyDownloadToken(
  orderId,
  token
) {
  const expected =
    createDownloadToken(orderId);

  if (
    !token ||
    token.length !== expected.length
  ) {
    return false;
  }

  return crypto.timingSafeEqual(
    Buffer.from(expected),
    Buffer.from(token)
  );
}

/* =========================================================
   VERIFICATION HMAC SHOPIFY
========================================================= */

function verifyShopifyHmac(
  rawBody,
  hmacHeader
) {
  if (
    !rawBody ||
    !hmacHeader ||
    !SHOPIFY_WEBHOOK_SECRET
  ) {
    return false;
  }

  const digest =
    crypto
      .createHmac(
        "sha256",
        SHOPIFY_WEBHOOK_SECRET
      )
      .update(rawBody)
      .digest("base64");

  const provided =
    Buffer.from(
      hmacHeader,
      "utf8"
    );

  const calculated =
    Buffer.from(
      digest,
      "utf8"
    );

  if (
    provided.length !==
    calculated.length
  ) {
    return false;
  }

  return crypto.timingSafeEqual(
    provided,
    calculated
  );
}

/* =========================================================
   SHOPIFY DOMAIN
========================================================= */

function normalizeShopDomain(domain) {
  let shop = clean(domain);

  shop = shop
    .replace(
      /^https?:\/\//i,
      ""
    )
    .replace(
      /\/.*$/,
      ""
    );

  if (
    !shop.endsWith(
      ".myshopify.com"
    )
  ) {
    shop =
      `${shop}.myshopify.com`;
  }

  return shop;
}

/* =========================================================
   TOKEN SHOPIFY
========================================================= */

let shopifyTokenCache = null;

async function getShopifyAccessToken() {
  if (
    shopifyTokenCache &&
    shopifyTokenCache.expiresAt >
      Date.now() + 60000
  ) {
    return shopifyTokenCache.token;
  }

  if (!SHOPIFY_SHOP_DOMAIN) {
    throw new Error(
      "SHOPIFY_SHOP_DOMAIN manquant."
    );
  }

  if (!SHOPIFY_CLIENT_ID) {
    throw new Error(
      "SHOPIFY_CLIENT_ID manquant."
    );
  }

  if (!SHOPIFY_CLIENT_SECRET) {
    throw new Error(
      "SHOPIFY_CLIENT_SECRET ou SHOPIFY_WEBHOOK_SECRET manquant."
    );
  }

  const shop =
    normalizeShopDomain(
      SHOPIFY_SHOP_DOMAIN
    );

  console.log(
    "Demande de token Shopify..."
  );

  const response =
    await fetch(
      `https://${shop}/admin/oauth/access_token`,
      {
        method: "POST",

        headers: {
          "Content-Type":
            "application/x-www-form-urlencoded"
        },

        body:
          new URLSearchParams({
            grant_type:
              "client_credentials",

            client_id:
              SHOPIFY_CLIENT_ID,

            client_secret:
              SHOPIFY_CLIENT_SECRET
          })
      }
    );

  const data =
    await response.json();

  if (
    !response.ok ||
    !data.access_token
  ) {
    console.error(
      "Reponse Shopify token :",
      data
    );

    throw new Error(
      `Impossible d'obtenir le token Shopify (${response.status}).`
    );
  }

  shopifyTokenCache = {
    token:
      data.access_token,

    expiresAt:
      Date.now() +
      Number(
        data.expires_in || 86399
      ) * 1000
  };

  console.log(
    "Token Shopify obtenu."
  );

  return data.access_token;
}

/* =========================================================
   SHOPIFY GRAPHQL
========================================================= */

async function shopifyGraphQL(
  query,
  variables = {}
) {
  const token =
    await getShopifyAccessToken();

  const shop =
    normalizeShopDomain(
      SHOPIFY_SHOP_DOMAIN
    );

  const response =
    await fetch(
      `https://${shop}/admin/api/${SHOPIFY_API_VERSION}/graphql.json`,
      {
        method: "POST",

        headers: {
          "Content-Type":
            "application/json",

          "X-Shopify-Access-Token":
            token
        },

        body:
          JSON.stringify({
            query,
            variables
          })
      }
    );

  const data =
    await response.json();

  if (!response.ok) {
    console.error(
      "Shopify GraphQL HTTP :",
      response.status
    );

    console.error(data);

    throw new Error(
      `Shopify GraphQL HTTP ${response.status}`
    );
  }

  if (data.errors?.length) {
    console.error(
      "Shopify GraphQL errors :",
      JSON.stringify(
        data.errors
      )
    );

    throw new Error(
      data.errors
        .map(
          (error) =>
            error.message
        )
        .join(" | ")
    );
  }

  return data;
}

/* =========================================================
   VERIFICATION WEBHOOK
========================================================= */

async function ensureOrdersPaidWebhook() {
  console.log(
    "Verification du webhook orders/paid..."
  );

  if (!BASE_URL) {
    throw new Error(
      "BASE_URL manquant."
    );
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

  const result =
    await shopifyGraphQL(
      query
    );

  const subscriptions =
    result
      ?.data
      ?.webhookSubscriptions
      ?.edges || [];

  const existing =
    subscriptions.find(
      (edge) =>
        edge?.node?.topic ===
        "ORDERS_PAID"
    );

  if (existing) {
    console.log(
      `Webhook orders/paid deja present : ${existing.node.id}`
    );

    console.log(
      `URL : ${existing.node.uri || "non renseignee"}`
    );

    return existing.node;
  }

  console.log(
    "Aucun webhook orders/paid trouve. Creation..."
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

  const resultCreate =
    await shopifyGraphQL(
      mutation,
      {
        topic:
          "ORDERS_PAID",

        webhookSubscription: {
          uri: WEBHOOK_URL
        }
      }
    );

  const payload =
    resultCreate
      ?.data
      ?.webhookSubscriptionCreate;

  if (
    payload?.userErrors?.length
  ) {
    console.error(
      "Erreurs creation webhook :",
      payload.userErrors
    );

    throw new Error(
      payload.userErrors
        .map(
          (error) =>
            error.message
        )
        .join(" | ")
    );
  }

  if (
    !payload?.webhookSubscription
  ) {
    throw new Error(
      "Shopify n'a pas retourne le webhook cree."
    );
  }

  console.log(
    `Webhook orders/paid cree : ${payload.webhookSubscription.id}`
  );

  return payload.webhookSubscription;
}

/* =========================================================
   LETTRE PREMIUM
========================================================= */

function createPdf({
  type,
  firstName,
  lastName,
  houseKey,
  outputPath
}) {
  return new Promise(
    (resolve, reject) => {
      const normalizedHouse =
        normalizeHouse(
          houseKey
        );

      const house =
        HOUSES[
          normalizedHouse
        ];

      const style =
        HOUSE_STYLES[
          normalizedHouse
        ] ||
        HOUSE_STYLES.IGNIS;

      const doc =
        new PDFDocument({
          size: "A4",
          margin: 0,

          info: {
            Title:
              "Lettre d'admission - Academia Arcana",

            Author:
              "Academia Arcana",

            Subject:
              "Document d'admission personnalise"
          }
        });

      const stream =
        fs.createWriteStream(
          outputPath
        );

      stream.on(
        "finish",
        resolve
      );

      stream.on(
        "error",
        reject
      );

      doc.pipe(stream);

      const pageWidth =
        595.28;

      const pageHeight =
        841.89;

      const fullName =
        `${firstName} ${lastName}`
          .trim();

      const admissionNumber =
        `AA-${Date.now()
          .toString()
          .slice(-8)}`;

      const dateText =
        new Intl.DateTimeFormat(
          "fr-FR",
          {
            day: "numeric",
            month: "long",
            year: "numeric"
          }
        ).format(
          new Date()
        );

      /* =====================================================
         FOND
      ===================================================== */

      doc
        .rect(
          0,
          0,
          pageWidth,
          pageHeight
        )
        .fill("#FCFAF6");

      /* =====================================================
         CADRE
      ===================================================== */

      doc
        .lineWidth(2)
        .strokeColor(
          style.primary
        )
        .rect(
          24,
          24,
          pageWidth - 48,
          pageHeight - 48
        )
        .stroke();

      doc
        .lineWidth(0.7)
        .strokeColor(
          style.secondary
        )
        .rect(
          31,
          31,
          pageWidth - 62,
          pageHeight - 62
        )
        .stroke();

      /* =====================================================
         ORNEMENTS
      ===================================================== */

      function drawDiamond(
        x,
        y,
        rotation = 0
      ) {
        doc.save();

        doc.translate(
          x,
          y
        );

        doc.rotate(
          rotation
        );

        doc
          .lineWidth(1)
          .strokeColor(
            style.secondary
          );

        doc
          .moveTo(
            0,
            -7
          )
          .lineTo(
            7,
            0
          )
          .lineTo(
            0,
            7
          )
          .lineTo(
            -7,
            0
          )
          .closePath()
          .stroke();

        doc.restore();
      }

      drawDiamond(
        48,
        48
      );

      drawDiamond(
        pageWidth - 48,
        48,
        45
      );

      drawDiamond(
        48,
        pageHeight - 48,
        45
      );

      drawDiamond(
        pageWidth - 48,
        pageHeight - 48
      );

      /* =====================================================
         EN-TETE
      ===================================================== */

      doc
        .font(
          "Helvetica-Bold"
        )
        .fontSize(27)
        .fillColor(
          style.primary
        )
        .text(
          "ACADEMIA ARCANA",
          60,
          68,
          {
            width:
              pageWidth - 120,

            align:
              "center"
          }
        );

      doc
        .font(
          "Helvetica"
        )
        .fontSize(9)
        .fillColor(
          "#6F6874"
        )
        .text(
          "ECOLE DES ARTS MAGIQUES",
          60,
          103,
          {
            width:
              pageWidth - 120,

            align:
              "center",

            characterSpacing:
              2
          }
        );

      /* =====================================================
         ORNEMENT CENTRAL
      ===================================================== */

      doc
        .moveTo(
          145,
          130
        )
        .lineTo(
          250,
          130
        )
        .lineWidth(0.8)
        .strokeColor(
          style.secondary
        )
        .stroke();

      doc
        .moveTo(
          345,
          130
        )
        .lineTo(
          450,
          130
        )
        .lineWidth(0.8)
        .strokeColor(
          style.secondary
        )
        .stroke();

      doc
        .font(
          "Helvetica-Bold"
        )
        .fontSize(10)
        .fillColor(
          style.secondary
        )
        .text(
          "A",
          281,
          121,
          {
            width: 34,
            align: "center"
          }
        );

      /* =====================================================
         TITRE
      ===================================================== */

      doc
        .font(
          "Times-Bold"
        )
        .fontSize(27)
        .fillColor(
          "#29232D"
        )
        .text(
          "LETTRE D'ADMISSION",
          60,
          158,
          {
            width:
              pageWidth - 120,

            align:
              "center"
          }
        );

      doc
        .font(
          "Helvetica"
        )
        .fontSize(8)
        .fillColor(
          "#77717B"
        )
        .text(
          "DOCUMENT OFFICIEL DE L'ACADEMIA ARCANA",
          60,
          193,
          {
            width:
              pageWidth - 120,

            align:
              "center",

            characterSpacing:
              1
          }
        );

      /* =====================================================
         SCEAU
      ===================================================== */

      const sealX =
        pageWidth / 2;

      const sealY =
        268;

      doc
        .lineWidth(2)
        .strokeColor(
          style.primary
        )
        .circle(
          sealX,
          sealY,
          48
        )
        .stroke();

      doc
        .lineWidth(0.8)
        .strokeColor(
          style.secondary
        )
        .circle(
          sealX,
          sealY,
          40
        )
        .stroke();

      doc
        .font(
          "Helvetica-Bold"
        )
        .fontSize(25)
        .fillColor(
          style.primary
        )
        .text(
          style.symbol,
          sealX - 25,
          sealY - 17,
          {
            width: 50,
            align: "center"
          }
        );

      doc
        .font(
          "Helvetica"
        )
        .fontSize(6.5)
        .fillColor(
          style.primary
        )
        .text(
          "ACADEMIA ARCANA",
          sealX - 40,
          sealY + 23,
          {
            width: 80,
            align: "center",
            characterSpacing: 0.7
          }
        );

      /* =====================================================
         DESTINATAIRE
      ===================================================== */

      doc
        .font(
          "Helvetica"
        )
        .fontSize(8.5)
        .fillColor(
          "#77717B"
        )
        .text(
          "CETTE LETTRE EST OFFICIELLEMENT ADRESSEE A",
          60,
          340,
          {
            width:
              pageWidth - 120,

            align:
              "center",

            characterSpacing:
              0.8
          }
        );

      doc
        .font(
          "Times-Bold"
        )
        .fontSize(25)
        .fillColor(
          "#211B26"
        )
        .text(
          fullName ||
            "Apprenti Arcana",
          60,
          363,
          {
            width:
              pageWidth - 120,

            align:
              "center"
          }
        );

      /* =====================================================
         MAISON
      ===================================================== */

      doc
        .roundedRect(
          110,
          415,
          pageWidth - 220,
          76,
          8
        )
        .fill(
          style.light
        );

      doc
        .roundedRect(
          110,
          415,
          pageWidth - 220,
          76,
          8
        )
        .lineWidth(1)
        .strokeColor(
          style.secondary
        )
        .stroke();

      doc
        .font(
          "Helvetica"
        )
        .fontSize(8)
        .fillColor(
          "#77717B"
        )
        .text(
          "MAISON D'APPARTENANCE",
          130,
          429,
          {
            width:
              pageWidth - 260,

            align:
              "center",

            characterSpacing:
              1
          }
        );

      doc
        .font(
          "Times-Bold"
        )
        .fontSize(22)
        .fillColor(
          style.primary
        )
        .text(
          house.name,
          130,
          447,
          {
            width:
              pageWidth - 260,

            align:
              "center"
          }
        );

      doc
        .font(
          "Helvetica"
        )
        .fontSize(8)
        .fillColor(
          "#625D66"
        )
        .text(
          `${house.element}  -  ${house.animal}`,
          130,
          473,
          {
            width:
              pageWidth - 260,

            align:
              "center"
          }
        );

      /* =====================================================
         TEXTE
      ===================================================== */

      const bodyX =
        92;

      const bodyWidth =
        pageWidth - 184;

      doc
        .font(
          "Times-Roman"
        )
        .fontSize(12)
        .fillColor(
          "#332E35"
        )
        .text(
          `Cher ${firstName || "apprenti"},`,
          bodyX,
          535,
          {
            width:
              bodyWidth
          }
        );

      doc
        .font(
          "Times-Roman"
        )
        .fontSize(11.5)
        .fillColor(
          "#3C3740"
        )
        .text(
          "Nous avons le plaisir de vous annoncer votre admission a l'Academia Arcana. Votre parcours au sein de notre academie commence aujourd'hui.",
          bodyX,
          570,
          {
            width:
              bodyWidth,

            align:
              "justify",

            lineGap:
              4
          }
        );

      doc
        .font(
          "Times-Roman"
        )
        .fontSize(11.5)
        .fillColor(
          "#3C3740"
        )
        .text(
          `Votre maison, ${house.name}, vous ouvre desormais ses portes. Elle represente ${house.description}.`,
          bodyX,
          635,
          {
            width:
              bodyWidth,

            align:
              "justify",

            lineGap:
              4
          }
        );

      doc
        .font(
          "Times-Roman"
        )
        .fontSize(11.5)
        .fillColor(
          "#3C3740"
        )
        .text(
          "Gardez precieusement cette lettre. Elle marque le commencement d'une nouvelle aventure.",
          bodyX,
          700,
          {
            width:
              bodyWidth,

            align:
              "justify",

            lineGap:
              4
          }
        );

      /* =====================================================
         SIGNATURE
      ===================================================== */

      doc
        .font(
          "Times-Italic"
        )
        .fontSize(15)
        .fillColor(
          style.primary
        )
        .text(
          "La Direction",
          350,
          750,
          {
            width: 135,
            align: "center"
          }
        );

      doc
        .font(
          "Helvetica"
        )
        .fontSize(7)
        .fillColor(
          "#77717B"
        )
        .text(
          "ACADEMIA ARCANA",
          350,
          771,
          {
            width: 135,
            align: "center",
            characterSpacing: 0.7
          }
        );

      doc
        .moveTo(
          340,
          787
        )
        .lineTo(
          495,
          787
        )
        .lineWidth(0.6)
        .strokeColor(
          "#AAA2AD"
        )
        .stroke();

      /* =====================================================
         PIED DE PAGE
      ===================================================== */

      doc
        .font(
          "Helvetica"
        )
        .fontSize(7.5)
        .fillColor(
          "#77717B"
        )
        .text(
          `N° ${admissionNumber}`,
          60,
          807,
          {
            width: 150
          }
        );

      doc
        .text(
          dateText,
          210,
          807,
          {
            width: 175,
            align: "center"
          }
        );

      doc
        .text(
          "ACADEMIA ARCANA",
          385,
          807,
          {
            width: 150,
            align: "right"
          }
        );

      doc.end();
    }
  );
}

/* =========================================================
   TYPE DE DOCUMENT
========================================================= */

function getDocumentType(
  productTitle
) {
  const title =
    clean(
      productTitle
    ).toLowerCase();

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
   TRAITEMENT COMMANDE
========================================================= */

async function processOrder(order) {
  const orderId =
    String(
      order?.id ||
      `ARCANA-${Date.now()}`
    );

  const firstName =
    getCustomerFirstName(
      order
    ) ||
    "Apprenti";

  const lastName =
    getCustomerLastName(
      order
    );

  const lineItems =
    Array.isArray(
      order?.line_items
    )
      ? order.line_items
      : [];

  const personalizedItems =
    lineItems.filter(
      (item) => {
        const flag =
          getLineProperty(
            item,
            "_arcana_personalized"
          );

        return (
          flag.toLowerCase() ===
          "true"
        );
      }
    );

  if (
    !personalizedItems.length
  ) {
    console.log(
      `Aucune ligne personnalisee pour ${orderId}.`
    );

    return {
      generated: false,

      reason:
        "no_personalized_items"
    };
  }

  const safeOrderId =
    orderId.replace(
      /[^a-zA-Z0-9_-]/g,
      "_"
    );

  const orderDir =
    path.join(
      STORAGE_DIR,
      safeOrderId
    );

  fs.mkdirSync(
    orderDir,
    {
      recursive: true
    }
  );

  const generatedFiles =
    [];

  for (
    const item
    of personalizedItems
  ) {
    const itemFirstName =
      getLineProperty(
        item,
        "Prénom"
      ) ||
      getLineProperty(
        item,
        "Prenom"
      ) ||
      firstName;

    const itemLastName =
      getLineProperty(
        item,
        "Nom"
      ) ||
      lastName;

    const house =
      normalizeHouse(
        getLineProperty(
          item,
          "Maison"
        )
      );

    const type =
      getDocumentType(
        item.title
      );

    const safeTitle =
      clean(
        item.title
      )
        .replace(
          /[^a-zA-Z0-9À-ÿ_-]+/g,
          "_"
        )
        .slice(
          0,
          80
        ) ||
      "document";

    const filename =
      `${safeTitle}_${itemFirstName}_${itemLastName}.pdf`
        .replace(
          /[^a-zA-Z0-9À-ÿ_.-]/g,
          "_"
        );

    const pdfPath =
      path.join(
        orderDir,
        filename
      );

    console.log(
      `Generation PDF : ${filename}`
    );

    await createPdf({
      type,
      firstName:
        itemFirstName,
      lastName:
        itemLastName,
      houseKey:
        house,
      outputPath:
        pdfPath
    });

    generatedFiles.push({
      path:
        pdfPath,

      filename
    });
  }

  /* =======================================================
     ZIP
  ======================================================= */

  const zipFilename =
    `academia-arcana-${safeOrderId}.zip`;

  const zipPath =
    path.join(
      STORAGE_DIR,
      zipFilename
    );

  await new Promise(
    (
      resolve,
      reject
    ) => {
      const output =
        fs.createWriteStream(
          zipPath
        );

      const archive =
        archiver(
          "zip",
          {
            zlib: {
              level: 9
            }
          }
        );

      output.on(
        "close",
        resolve
      );

      output.on(
        "error",
        reject
      );

      archive.on(
        "error",
        reject
      );

      archive.pipe(
        output
      );

      for (
        const file
        of generatedFiles
      ) {
        archive.file(
          file.path,
          {
            name:
              file.filename
          }
        );
      }

      archive.finalize();
    }
  );

  /* =======================================================
     LIEN SECURISE
  ======================================================= */

  const token =
    createDownloadToken(
      orderId
    );

  const downloadUrl =
    `${BASE_URL}/download/${encodeURIComponent(
      orderId
    )}/${token}`;

  console.log(
    `ZIP genere : ${zipFilename}`
  );

  console.log(
    `Lien : ${downloadUrl}`
  );

  /* =======================================================
     EMAIL OPTIONNEL
  ======================================================= */

  if (
    process.env.SMTP_HOST &&
    process.env.SMTP_USER &&
    process.env.SMTP_PASS &&
    order?.email
  ) {
    try {
      const transporter =
        nodemailer.createTransport(
          {
            host:
              process.env.SMTP_HOST,

            port:
              Number(
                process.env.SMTP_PORT
              ) || 587,

            secure:
              String(
                process.env.SMTP_SECURE
              ).toLowerCase() ===
              "true",

            auth: {
              user:
                process.env.SMTP_USER,

              pass:
                process.env.SMTP_PASS
            }
          }
        );

      await transporter.sendMail(
        {
          from:
            process.env.SMTP_FROM ||
            process.env.SMTP_USER,

          to:
            order.email,

          subject:
            "Votre document Academia Arcana",

          text:
            `Votre document personnalise est pret.\n\n${downloadUrl}`
        }
      );

      console.log(
        `Email envoye a ${order.email}`
      );
    } catch (
      emailError
    ) {
      console.error(
        "Erreur email :",
        emailError.message
      );
    }
  }

  return {
    generated:
      true,

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
        (file) =>
          file.filename
      ),

    zipFilename,

    downloadUrl
  };
}

/* =========================================================
   PAGE RACINE
========================================================= */

app.get(
  "/",
  (req, res) => {
    res.status(200).send(`
      <!doctype html>

      <html lang="fr">

      <head>
        <meta charset="utf-8">

        <meta name="viewport"
          content="width=device-width, initial-scale=1">

        <title>Academia Arcana</title>

        <style>

          * {
            box-sizing: border-box;
          }

          body {
            margin: 0;
            min-height: 100vh;

            display: flex;
            align-items: center;
            justify-content: center;

            background:
              radial-gradient(
                circle at top,
                #21162d,
                #08060c 65%
              );

            color: white;

            font-family:
              Arial,
              sans-serif;

            text-align: center;
          }

          .box {
            width: min(600px, 90%);
            padding: 60px 40px;

            border:
              1px solid
              rgba(255,255,255,.15);

            border-radius: 20px;

            background:
              rgba(255,255,255,.04);

            box-shadow:
              0 30px 80px
              rgba(0,0,0,.4);
          }

          h1 {
            margin: 0 0 15px;

            font-size: 42px;

            letter-spacing: 2px;
          }

          p {
            color: #bcb3c5;
          }

          .status {
            margin-top: 30px;

            color: #d8c0e8;
          }

        </style>
      </head>

      <body>

        <div class="box">

          <h1>
            Academia Arcana
          </h1>

          <p>
            Générateur de documents personnalisés
          </p>

          <p class="status">
            Service opérationnel
          </p>

        </div>

      </body>

      </html>
    `);
  }
);

/* =========================================================
   HEALTH CHECK
========================================================= */

app.get(
  "/health",
  (req, res) => {
    res.json({
      ok: true,

      service:
        "academia-arcana-generator"
    });
  }
);

/* =========================================================
   WEBHOOK SHOPIFY
========================================================= */

app.post(
  "/webhooks/orders-paid",

  express.raw({
    type:
      "application/json"
  }),

  async (
    req,
    res
  ) => {
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
        `Webhook orders/paid recu${
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
          "HMAC Shopify invalide."
        );

        return res
          .status(401)
          .send(
            "Invalid HMAC"
          );
      }

      let order;

      try {
        order =
          JSON.parse(
            req.body.toString(
              "utf8"
            )
          );
      } catch (
        error
      ) {
        console.error(
          "JSON webhook invalide."
        );

        return res
          .status(400)
          .send(
            "Invalid JSON"
          );
      }

      /* Shopify recoit rapidement la confirmation */

      res
        .status(200)
        .send("OK");

      /* Traitement de la commande */

      try {
        const result =
          await processOrder(
            order
          );

        console.log(
          "Commande traitee :",
          JSON.stringify(
            result
          )
        );
      } catch (
        error
      ) {
        console.error(
          "Erreur traitement commande :",
          error
        );
      }

    } catch (
      error
    ) {
      console.error(
        "Erreur webhook :",
        error
      );

      if (
        !res.headersSent
      ) {
        res
          .status(500)
          .send(
            "Webhook error"
          );
      }
    }
  }
);

/* =========================================================
   JSON POUR LES AUTRES ROUTES
========================================================= */

app.use(
  express.json()
);

/* =========================================================
   ROUTE TEST
========================================================= */

app.post(
  "/test/generate",

  async (
    req,
    res
  ) => {
    try {

      if (
        !ARCANA_TEST_SECRET
      ) {
        return res
          .status(503)
          .json({
            ok: false,

            error:
              "ARCANA_TEST_SECRET n'est pas configure sur Render."
          });
      }

      const providedSecret =
        req.get(
          "X-Arcana-Test-Secret"
        );

      if (
        !providedSecret ||
        providedSecret !==
          ARCANA_TEST_SECRET
      ) {
        return res
          .status(401)
          .json({
            ok: false,

            error:
              "Secret de test invalide."
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
              "Lettre d'admission - Academia Arcana",

            quantity:
              1,

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
        "Generation de test demandee."
      );

      const result =
        await processOrder(
          testOrder
        );

      return res.json({
        ok: true,

        test: true,

        ...result
      });

    } catch (
      error
    ) {

      console.error(
        "Erreur test :",
        error
      );

      return res
        .status(500)
        .json({
          ok: false,

          error:
            error.message ||
            "Erreur inconnue."
        });
    }
  }
);

/* =========================================================
   TELECHARGEMENT SECURISE
========================================================= */

app.get(
  "/download/:order/:token",

  (
    req,
    res
  ) => {
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
          .send(
            "Lien de telechargement invalide."
          );
      }

      const safeOrderId =
        orderId.replace(
          /[^a-zA-Z0-9_-]/g,
          "_"
        );

      const zipFilename =
        `academia-arcana-${safeOrderId}.zip`;

      const zipPath =
        path.join(
          STORAGE_DIR,
          zipFilename
        );

      if (
        !fs.existsSync(
          zipPath
        )
      ) {
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

    } catch (
      error
    ) {

      console.error(
        "Erreur telechargement :",
        error
      );

      return res
        .status(500)
        .send(
          "Erreur de telechargement."
        );
    }
  }
);

/* =========================================================
   404
========================================================= */

app.use(
  (
    req,
    res
  ) => {
    res
      .status(404)
      .json({
        ok: false,

        error:
          "Route introuvable."
      });
  }
);

/* =========================================================
   DEMARRAGE
========================================================= */

app.listen(
  PORT,
  () => {

    console.log(
      `Academia Arcana generator listening on :${PORT}`
    );

    console.log(
      "Verification du webhook orders/paid..."
    );

    setTimeout(
      async () => {

        try {

          await ensureOrdersPaidWebhook();

          console.log(
            "Verification Shopify terminee."
          );

          console.log(
            "Service Academia Arcana pret."
          );

        } catch (
          error
        ) {

          console.error(
            "Verification Shopify echouee :",
            error.message
          );
        }

      },
      1000
    );
  }
);
