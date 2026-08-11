// "/v1" a propósito: desde firebase-functions v6+, require('firebase-functions')
// apunta a la v2 (Cloud Run por debajo), cuya URL final no se conoce hasta
// desplegar. La v1 clásica sigue totalmente soportada y da una URL fija y
// conocida de antemano (https://REGION-PROYECTO.cloudfunctions.net/NOMBRE),
// que es lo que necesitamos para poder armar notification_url acá mismo.
const functions = require('firebase-functions/v1');
const { initializeApp } = require('firebase-admin/app');
const { getFirestore, FieldValue } = require('firebase-admin/firestore');
initializeApp();
const db = getFirestore();

const MP_API = 'https://api.mercadopago.com';

// La URL de este webhook es fija y conocida ANTES de desplegar porque son
// funciones de 1ra generación (us-central1 por default). Si en algún
// momento se cambia de región, hay que actualizar esto también.
const WEBHOOK_URL = 'https://us-central1-mercado-appp.cloudfunctions.net/webhookMercadoPago';

/**
 * Crea un cobro de MercadoPago por el monto exacto de una venta.
 * La app llama a esto desde el navegador (con el usuario ya logueado);
 * acá adentro es donde se usa el Access Token privado del negocio, que
 * nunca se manda al navegador.
 *
 * data: { monto: number, descripcion: string, idPago: string }
 * (idPago lo genera la app antes de llamar, para poder escuchar ese
 * mismo documento en Firestore y saber cuándo se aprobó el pago)
 */
exports.crearPreferenciaPago = functions.https.onCall(async (data, context) => {
  if (!context.auth) {
    throw new functions.https.HttpsError('unauthenticated', 'Hay que estar logueado');
  }
  const uid = context.auth.uid;
  const monto = Number(data.monto);
  const idPago = String(data.idPago || '');
  const descripcion = String(data.descripcion || 'Venta').slice(0, 200);
  if (!monto || monto <= 0) {
    throw new functions.https.HttpsError('invalid-argument', 'Monto inválido');
  }
  if (!idPago) {
    throw new functions.https.HttpsError('invalid-argument', 'Falta idPago');
  }

  const negocioSnap = await db.collection('negocios').doc(uid).get();
  const negocioData = negocioSnap.exists ? negocioSnap.data() : null;
  const token = negocioData && negocioData.negocio && negocioData.negocio.mercadoPagoAccessToken;
  if (!token) {
    throw new functions.https.HttpsError('failed-precondition', 'Este negocio todavía no cargó su Access Token de MercadoPago');
  }

  // Documento "pendiente" ANTES de llamar a MercadoPago: si algo falla
  // después de crear la preferencia, preferimos que quede un registro
  // pendiente antes que un pago fantasma sin rastro.
  await db.collection('pagosMercadoPago').doc(idPago).set({
    negocioUid: uid,
    monto,
    descripcion,
    estado: 'pendiente',
    fecha: FieldValue.serverTimestamp()
  });

  let mpResp;
  try {
    mpResp = await fetch(`${MP_API}/checkout/preferences`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        items: [{ title: descripcion, quantity: 1, unit_price: monto, currency_id: 'ARS' }],
        external_reference: idPago,
        notification_url: `${WEBHOOK_URL}?uid=${encodeURIComponent(uid)}`,
        // Sin back_urls / auto_return: el cliente paga desde el QR con su
        // propia app de MercadoPago, no necesita volver a ningún lado.
      })
    });
  } catch (e) {
    throw new functions.https.HttpsError('unavailable', 'No se pudo conectar con MercadoPago');
  }

  const pref = await mpResp.json();
  if (!mpResp.ok) {
    throw new functions.https.HttpsError('internal', (pref && pref.message) || 'MercadoPago rechazó la solicitud. Revisá que el Access Token sea válido.');
  }

  return { idPago, initPoint: pref.init_point };
});

/**
 * MercadoPago llama a esto solo (no lo llama la app) cada vez que cambia
 * el estado de un pago. Acá se confirma contra la propia API de
 * MercadoPago (nunca se confía en lo que venga en el pedido en sí, podría
 * ser cualquiera) antes de marcar algo como aprobado.
 */
exports.webhookMercadoPago = functions.https.onRequest(async (req, res) => {
  try {
    const uid = req.query.uid;
    const topic = req.query.topic || req.query.type || (req.body && req.body.type);
    const paymentId = req.query.id || req.query['data.id'] || (req.body && req.body.data && req.body.data.id);

    if (!uid || topic !== 'payment' || !paymentId) {
      res.sendStatus(200); // formato desconocido / notificación que no es de pago: se ignora, no es error
      return;
    }

    const negocioSnap = await db.collection('negocios').doc(String(uid)).get();
    const negocioData = negocioSnap.exists ? negocioSnap.data() : null;
    const token = negocioData && negocioData.negocio && negocioData.negocio.mercadoPagoAccessToken;
    if (!token) { res.sendStatus(200); return; }

    const pagoResp = await fetch(`${MP_API}/v1/payments/${paymentId}`, {
      headers: { 'Authorization': `Bearer ${token}` }
    });
    if (!pagoResp.ok) { res.sendStatus(200); return; }
    const pago = await pagoResp.json();

    const idPago = pago.external_reference;
    if (!idPago) { res.sendStatus(200); return; }

    const pagoDocRef = db.collection('pagosMercadoPago').doc(idPago);
    const pagoDoc = await pagoDocRef.get();
    // El documento pendiente lo creamos nosotros mismos con el uid correcto
    // al generar la preferencia — si no coincide con el uid de esta
    // notificación, no se toca (evita que alguien intente pisar el pago
    // de otro negocio mandando un uid ajeno al webhook).
    if (!pagoDoc.exists || pagoDoc.data().negocioUid !== String(uid)) { res.sendStatus(200); return; }

    if (pago.status === 'approved') {
      await pagoDocRef.update({ estado: 'aprobado', pagoIdMercadoPago: pago.id, fechaAprobado: FieldValue.serverTimestamp() });
    } else if (pago.status === 'rejected' || pago.status === 'cancelled') {
      await pagoDocRef.update({ estado: 'rechazado' });
    }
    res.sendStatus(200);
  } catch (e) {
    // Siempre 200: si le devolvemos error, MercadoPago reintenta sin parar.
    // El error queda en los logs de Cloud Functions para revisar a mano.
    console.error('Error en webhookMercadoPago:', e);
    res.sendStatus(200);
  }
});
