const forge = require('node-forge');
const { XMLParser } = require('fast-xml-parser');
const { initializeApp, getApps, cert } = require('firebase-admin/app');
const { getFirestore } = require('firebase-admin/firestore');
const { getAuth } = require('firebase-admin/auth');

if (!getApps().length) {
  initializeApp({ credential: cert(JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT)) });
}
const db = getFirestore();
const authAdmin = getAuth();
const xmlParser = new XMLParser({ ignoreAttributes: true, removeNSPrefix: true });

const URLS = {
  homologacion: {
    wsaa: 'https://wsaahomo.afip.gov.ar/ws/services/LoginCms',
    wsfe: 'https://wswhomo.afip.gov.ar/wsfev1/service.asmx'
  },
  produccion: {
    wsaa: 'https://wsaa.afip.gov.ar/ws/services/LoginCms',
    wsfe: 'https://servicios1.afip.gov.ar/wsfev1/service.asmx'
  }
};

// Argentina es UTC-3 fijo, sin horario de verano — así que se puede
// calcular a mano sin depender de la zona horaria del servidor donde
// corra esta función (Netlify corre en UTC).
function fechaAFIP(date) {
  const corrida = new Date(date.getTime() - 3 * 60 * 60 * 1000);
  return corrida.toISOString().slice(0, 19) + '-03:00';
}
function fechaCorta(date) {
  const corrida = new Date(date.getTime() - 3 * 60 * 60 * 1000);
  return corrida.toISOString().slice(0, 10).replace(/-/g, '');
}

// Verificado por separado con OpenSSL antes de usarlo acá (ver sesión de
// pruebas): esta firma CMS es la parte más delicada de toda la
// integración — un error acá hace fallar TODO el resto silenciosamente.
function firmarCMS(xml, certPem, keyPem) {
  const cert = forge.pki.certificateFromPem(certPem);
  const privateKey = forge.pki.privateKeyFromPem(keyPem);
  const p7 = forge.pkcs7.createSignedData();
  p7.content = forge.util.createBuffer(xml, 'utf8');
  p7.addCertificate(cert);
  p7.addSigner({
    key: privateKey,
    certificate: cert,
    digestAlgorithm: forge.pki.oids.sha256,
    authenticatedAttributes: [
      { type: forge.pki.oids.contentType, value: forge.pki.oids.data },
      { type: forge.pki.oids.messageDigest },
      { type: forge.pki.oids.signingTime, value: new Date() }
    ]
  });
  p7.sign({ detached: false });
  const der = forge.asn1.toDer(p7.toAsn1()).getBytes();
  return forge.util.encode64(der);
}

async function loginWSAA(certPem, keyPem, homologacion) {
  const ahora = new Date();
  const xml =
    '<?xml version="1.0" encoding="UTF-8"?>' +
    '<loginTicketRequest version="1.0">' +
    '<header>' +
    `<uniqueId>${Math.floor(ahora.getTime() / 1000)}</uniqueId>` +
    `<generationTime>${fechaAFIP(new Date(ahora.getTime() - 60000))}</generationTime>` +
    `<expirationTime>${fechaAFIP(new Date(ahora.getTime() + 10 * 60000))}</expirationTime>` +
    '</header>' +
    '<service>wsfe</service>' +
    '</loginTicketRequest>';
  const cms = firmarCMS(xml, certPem, keyPem);
  const soapBody =
    '<?xml version="1.0" encoding="UTF-8"?>' +
    '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:wsaa="http://wsaa.view.sua.dvadac.desein.afip.gov">' +
    '<soapenv:Header/>' +
    '<soapenv:Body>' +
    `<wsaa:loginCms><wsaa:in0>${cms}</wsaa:in0></wsaa:loginCms>` +
    '</soapenv:Body>' +
    '</soapenv:Envelope>';

  const url = URLS[homologacion ? 'homologacion' : 'produccion'].wsaa;
  const resp = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'text/xml; charset=UTF-8', SOAPAction: 'urn:LoginCms' },
    body: soapBody
  });
  const texto = await resp.text();
  if (!resp.ok) throw new Error('WSAA respondió ' + resp.status + ': ' + texto.slice(0, 400));

  // La respuesta trae el XML del ticket ESCAPADO adentro de <loginCmsReturn>
  // (un XML dentro de otro XML), así que hace falta desescaparlo antes de
  // volver a parsear.
  const matchReturn = texto.match(/<loginCmsReturn>([\s\S]*?)<\/loginCmsReturn>/);
  if (!matchReturn) throw new Error('WSAA no devolvió loginCmsReturn: ' + texto.slice(0, 500));
  const innerXml = matchReturn[1]
    .replace(/&lt;/g, '<').replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"').replace(/&apos;/g, "'").replace(/&amp;/g, '&');
  const token = (innerXml.match(/<token>([\s\S]*?)<\/token>/) || [])[1];
  const sign = (innerXml.match(/<sign>([\s\S]*?)<\/sign>/) || [])[1];
  const expirationTime = (innerXml.match(/<expirationTime>([\s\S]*?)<\/expirationTime>/) || [])[1];
  if (!token || !sign) throw new Error('WSAA no devolvió token/sign. Revisá que el certificado sea válido y esté adherido al servicio wsfe.');
  return { token, sign, expirationTime };
}

// El ticket de WSAA dura ~12hs — se cachea por negocio en Firestore para
// no volver a autenticar en cada venta (AFIP podría rechazar por exceso
// de pedidos de login si se hiciera en cada factura).
async function obtenerAuthCacheada(uid, certPem, keyPem, homologacion) {
  const cacheRef = db.collection('negocios').doc(uid).collection('_privado').doc('afipAuth');
  const cacheSnap = await cacheRef.get();
  if (cacheSnap.exists) {
    const c = cacheSnap.data();
    if (c.homologacion === homologacion && c.expirationTime && new Date(c.expirationTime).getTime() - Date.now() > 5 * 60000) {
      return { token: c.token, sign: c.sign };
    }
  }
  const auth = await loginWSAA(certPem, keyPem, homologacion);
  await cacheRef.set({ token: auth.token, sign: auth.sign, expirationTime: auth.expirationTime, homologacion });
  return auth;
}

function soapWSFE(homologacion, metodo, cuerpoInterno) {
  return fetch(URLS[homologacion ? 'homologacion' : 'produccion'].wsfe, {
    method: 'POST',
    headers: {
      'Content-Type': 'text/xml; charset=UTF-8',
      SOAPAction: `http://ar.gov.afip.dif.FEV1/${metodo}`
    },
    body:
      '<?xml version="1.0" encoding="UTF-8"?>' +
      '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:ar="http://ar.gov.afip.dif.FEV1/">' +
      '<soapenv:Header/>' +
      `<soapenv:Body>${cuerpoInterno}</soapenv:Body>` +
      '</soapenv:Envelope>'
  });
}

async function obtenerUltimoComprobante(auth, cuit, ptoVta, cbteTipo, homologacion) {
  const cuerpo =
    '<ar:FECompUltimoAutorizado>' +
    `<ar:Auth><ar:Token>${auth.token}</ar:Token><ar:Sign>${auth.sign}</ar:Sign><ar:Cuit>${cuit}</ar:Cuit></ar:Auth>` +
    `<ar:PtoVta>${ptoVta}</ar:PtoVta><ar:CbteTipo>${cbteTipo}</ar:CbteTipo>` +
    '</ar:FECompUltimoAutorizado>';
  const resp = await soapWSFE(homologacion, 'FECompUltimoAutorizado', cuerpo);
  const texto = await resp.text();
  if (!resp.ok) throw new Error('AFIP (FECompUltimoAutorizado) respondió ' + resp.status + ': ' + texto.slice(0, 400));
  const parsed = xmlParser.parse(texto);
  const resultado = parsed?.Envelope?.Body?.FECompUltimoAutorizadoResponse?.FECompUltimoAutorizadoResult;
  if (!resultado) throw new Error('No se pudo leer la respuesta de FECompUltimoAutorizado: ' + texto.slice(0, 500));
  if (resultado.Errors) {
    const err = resultado.Errors.Err;
    const lista = Array.isArray(err) ? err : [err];
    throw new Error('AFIP rechazó la consulta: ' + lista.map(e => `[${e.Code}] ${e.Msg}`).join(' | '));
  }
  return Number(resultado.CbteNro || 0);
}

// Se factura como Consumidor Final (DocTipo 99, DocNro 0) por default. Por
// una regla de AFIP (RG4444), a partir de cierto monto YA NO alcanza con
// Consumidor Final y hace falta el documento real del comprador — ese
// límite lo fija AFIP y cambia con el tiempo, así que si una venta grande
// es rechazada por este motivo, hay que facturar esa puntualmente con el
// DNI del cliente desde otro lado (AFIP "Comprobantes en línea") hasta
// que se sume esa opción acá.
async function solicitarCAE({ auth, cuit, ptoVta, cbteTipo, cbteNro, importe, fecha, homologacion }) {
  const fechaCbte = fechaCorta(fecha);
  const cuerpo =
    '<ar:FECAESolicitar>' +
    `<ar:Auth><ar:Token>${auth.token}</ar:Token><ar:Sign>${auth.sign}</ar:Sign><ar:Cuit>${cuit}</ar:Cuit></ar:Auth>` +
    '<ar:FeCAEReq>' +
    `<ar:FeCabReq><ar:CantReg>1</ar:CantReg><ar:PtoVta>${ptoVta}</ar:PtoVta><ar:CbteTipo>${cbteTipo}</ar:CbteTipo></ar:FeCabReq>` +
    '<ar:FeDetReq><ar:FECAEDetRequest>' +
    '<ar:Concepto>1</ar:Concepto>' +
    '<ar:DocTipo>99</ar:DocTipo>' +
    '<ar:DocNro>0</ar:DocNro>' +
    `<ar:CbteDesde>${cbteNro}</ar:CbteDesde>` +
    `<ar:CbteHasta>${cbteNro}</ar:CbteHasta>` +
    `<ar:CbteFch>${fechaCbte}</ar:CbteFch>` +
    `<ar:ImpTotal>${importe.toFixed(2)}</ar:ImpTotal>` +
    '<ar:ImpTotConc>0.00</ar:ImpTotConc>' +
    `<ar:ImpNeto>${importe.toFixed(2)}</ar:ImpNeto>` +
    '<ar:ImpOpEx>0.00</ar:ImpOpEx>' +
    '<ar:ImpTrib>0.00</ar:ImpTrib>' +
    '<ar:ImpIVA>0.00</ar:ImpIVA>' +
    '<ar:MonId>PES</ar:MonId>' +
    '<ar:MonCotiz>1</ar:MonCotiz>' +
    '<ar:CondicionIVAReceptorId>5</ar:CondicionIVAReceptorId>' +
    '</ar:FECAEDetRequest></ar:FeDetReq>' +
    '</ar:FeCAEReq>' +
    '</ar:FECAESolicitar>';
  const resp = await soapWSFE(homologacion, 'FECAESolicitar', cuerpo);
  const texto = await resp.text();
  if (!resp.ok) throw new Error('AFIP (FECAESolicitar) respondió ' + resp.status + ': ' + texto.slice(0, 400));
  const parsed = xmlParser.parse(texto);
  const resultado = parsed?.Envelope?.Body?.FECAESolicitarResponse?.FECAESolicitarResult;
  if (!resultado) throw new Error('No se pudo leer la respuesta de FECAESolicitar: ' + texto.slice(0, 500));
  if (resultado.Errors) {
    const err = resultado.Errors.Err;
    const lista = Array.isArray(err) ? err : [err];
    throw new Error('AFIP rechazó la factura: ' + lista.map(e => `[${e.Code}] ${e.Msg}`).join(' | '));
  }
  const det = resultado.FeDetResp && resultado.FeDetResp.FECAEDetResponse;
  if (!det || det.Resultado !== 'A') {
    const obs = det && det.Obs && det.Obs.Observaciones;
    const listaObs = obs ? (Array.isArray(obs) ? obs : [obs]) : [];
    throw new Error('AFIP no aprobó la factura' + (listaObs.length ? ': ' + listaObs.map(o => `[${o.Code}] ${o.Msg}`).join(' | ') : ''));
  }
  return { cae: String(det.CAE), caeVencimiento: String(det.CAEFchVto), cbteNro, cbteTipo, ptoVta };
}

function armarQR({ cuit, ptoVta, cbteTipo, cbteNro, importe, fecha, cae }) {
  const datos = {
    ver: 1,
    fecha: fechaCorta(fecha).replace(/(\d{4})(\d{2})(\d{2})/, '$1-$2-$3'),
    cuit: Number(cuit),
    ptoVta: Number(ptoVta),
    tipoCmp: Number(cbteTipo),
    nroCmp: Number(cbteNro),
    importe: Number(importe.toFixed(2)),
    moneda: 'PES',
    ctz: 1,
    tipoDocRec: 99,
    nroDocRec: 0,
    tipoCodAut: 'E',
    codAut: Number(cae)
  };
  const b64 = Buffer.from(JSON.stringify(datos), 'utf8').toString('base64');
  return `https://www.afip.gob.ar/fe/qr/?p=${b64}`;
}

exports.handler = async (event) => {
  if (event.httpMethod !== 'POST') return { statusCode: 405, body: 'Method not allowed' };
  try {
    const authHeader = event.headers.authorization || event.headers.Authorization || '';
    const idToken = authHeader.replace(/^Bearer\s+/i, '');
    if (!idToken) return { statusCode: 401, body: JSON.stringify({ error: 'Falta autenticación' }) };
    const decoded = await authAdmin.verifyIdToken(idToken);
    const uid = decoded.uid;

    const body = JSON.parse(event.body || '{}');
    const importe = Number(body.importe);
    if (!importe || importe <= 0) return { statusCode: 400, body: JSON.stringify({ error: 'Importe inválido' }) };

    const negocioSnap = await db.collection('negocios').doc(uid).get();
    const negocio = negocioSnap.exists ? negocioSnap.data().negocio : null;
    const afipCfg = negocio && negocio.afip;
    if (!afipCfg || !afipCfg.certificado || !afipCfg.clavePrivada || !afipCfg.cuit || !afipCfg.puntoVenta) {
      return { statusCode: 400, body: JSON.stringify({ error: 'Este negocio todavía no configuró su facturación de AFIP' }) };
    }
    const homologacion = afipCfg.modo !== 'produccion'; // homologación por default: hay que elegir producción a propósito
    const cbteTipo = 11; // Factura C (monotributista) — única soportada por ahora

    const auth = await obtenerAuthCacheada(uid, afipCfg.certificado, afipCfg.clavePrivada, homologacion);
    const ultimoNro = await obtenerUltimoComprobante(auth, afipCfg.cuit, afipCfg.puntoVenta, cbteTipo, homologacion);
    const cbteNro = ultimoNro + 1;
    const fecha = new Date();

    const resultado = await solicitarCAE({
      auth, cuit: afipCfg.cuit, ptoVta: afipCfg.puntoVenta, cbteTipo, cbteNro, importe, fecha, homologacion
    });
    const qrUrl = armarQR({ cuit: afipCfg.cuit, ptoVta: afipCfg.puntoVenta, cbteTipo, cbteNro, importe, fecha, cae: resultado.cae });

    return {
      statusCode: 200,
      body: JSON.stringify({
        cae: resultado.cae,
        caeVencimiento: resultado.caeVencimiento,
        puntoVenta: afipCfg.puntoVenta,
        numeroComprobante: cbteNro,
        tipoComprobante: 'Factura C',
        qrUrl,
        homologacion
      })
    };
  } catch (e) {
    return { statusCode: 500, body: JSON.stringify({ error: String((e && e.message) || e) }) };
  }
};
