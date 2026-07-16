/**
 * FlyPaper — Panel SOC unificado (/admin)
 * Pestañas SPA, Fetch API y sanitización HTML.
 */
(function () {
  'use strict';

  const TITULOS = {
    general: 'Vista General',
    monitor: 'Monitor Real-Time',
    perimetro: 'Perímetro / Bots',
    usuarios: 'Usuarios (señuelo)',
    reportes: 'Reportes de Seguridad',
    mapa: 'Mapa de Amenazas',
  };

  const COLORES_GRAVEDAD = {
    Crítica: '#f85149',
    Alta: '#d29922',
    Sospechoso: '#e3b341',
    'BOT / BLOQUEADO': '#a855f7',
  };

  const COLOR_MARCADOR_BOT = '#7c3aed';

  let monitorCargado = false;
  let mapaInicializado = false;
  let mapaLeaflet = null;
  let capaMarcadores = null;

  /** Escapa texto para insertar en innerHTML de forma segura. */
  function esc(texto) {
    return String(texto ?? '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  function esAdmin() {
    return document.body.dataset.esAdmin === '1';
  }

  function mostrarBanner(mensaje, tipo) {
    const banner = document.getElementById('soc-banner');
    if (!banner) return;
    banner.textContent = mensaje;
    banner.className = 'soc-banner visible ' + (tipo || 'error');
    clearTimeout(banner._timer);
    banner._timer = setTimeout(function () {
      banner.classList.remove('visible');
    }, 6000);
  }

  async function fetchJson(url, opciones) {
    const res = await fetch(url, Object.assign({ credentials: 'same-origin' }, opciones || {}));
    const json = await res.json().catch(function () {
      return { status: 'error', mensaje: 'Respuesta no JSON', data: [] };
    });
    if (!res.ok || json.status === 'error') {
      throw new Error(json.mensaje || 'HTTP ' + res.status);
    }
    return json;
  }

  function extraerData(json, claveLegacy) {
    if (Array.isArray(json.data)) return json.data;
    if (json.data != null && typeof json.data === 'object' && !Array.isArray(json.data)) {
      return json.data;
    }
    if (claveLegacy && json[claveLegacy] != null) return json[claveLegacy];
    return json.data ?? [];
  }

  function activarTab(tab) {
    const botones = document.querySelectorAll('[data-tab]');
    const paneles = document.querySelectorAll('[data-panel]');
    botones.forEach(function (b) {
      b.classList.toggle('active', b.dataset.tab === tab);
    });
    paneles.forEach(function (p) {
      p.classList.toggle('active', p.dataset.panel === tab);
    });
    const titulo = document.getElementById('soc-titulo');
    if (titulo && TITULOS[tab]) titulo.textContent = TITULOS[tab];
    if (location.hash.replace('#', '') !== tab) {
      history.replaceState(null, '', '#'.concat(tab));
    }
  }

  function cargarTab(tab) {
    if (tab === 'general') return cargarGeneral();
    if (tab === 'perimetro') return cargarPerimetro();
    if (tab === 'usuarios') return cargarUsuarios();
    if (tab === 'reportes') return cargarReportesResumenes();
    if (tab === 'mapa') return cargarMapa();
    if (tab === 'monitor' && !monitorCargado) {
      monitorCargado = true;
      const iframe = document.getElementById('monitor-iframe');
      if (iframe && !iframe.src) iframe.src = '/admin/embed/monitor';
    }
  }

  function initTabs() {
    document.querySelectorAll('[data-tab]').forEach(function (btn) {
      btn.addEventListener('click', function () {
        const tab = btn.dataset.tab;
        activarTab(tab);
        cargarTab(tab);
      });
    });

    const hash = (location.hash || '').replace('#', '');
    const validas = ['general', 'monitor', 'perimetro', 'usuarios', 'reportes', 'mapa'];
    const tabInicial = validas.indexOf(hash) >= 0 ? hash : 'general';
    if (!esAdmin() && ['usuarios', 'reportes', 'mapa'].indexOf(tabInicial) >= 0) {
      activarTab('general');
      cargarGeneral();
      return;
    }
    activarTab(tabInicial);
    cargarTab(tabInicial);
  }

  /** ——— General ——— */
  async function cargarGeneral() {
    try {
      const [status, conexiones, critico] = await Promise.all([
        fetchJson('/admin/api/honeypot-status'),
        fetchJson('/admin/api/ultimas-conexiones'),
        fetchJson('/admin/api/ultimo-critico'),
      ]);
      const stats = extraerData(status, null);
      pintarHoneypot(stats.activo != null ? stats : status);
      pintarConexiones(extraerData(conexiones, 'conexiones'));
      const ev = critico.evento ?? critico.data ?? null;
      pintarCritico(ev);
    } catch (err) {
      mostrarBanner('No se pudo cargar el dashboard general: ' + err.message);
      pintarConexiones([]);
      pintarCritico(null);
    }
  }

  function pintarHoneypot(s) {
    const el = document.getElementById('widget-honeypot');
    if (!el) return;
    const redisOk = s.redis_ok !== false && s.ngwaf && s.ngwaf.redis_ok !== false;
    const circuitos = s.circuitos_abiertos || (s.ngwaf && s.ngwaf.circuitos_abiertos) || {};
    const circuitoTxt =
      circuitos.abuseipdb || circuitos.virustotal
        ? 'Circuit breaker abierto (APIs)'
        : 'APIs OK';
    el.innerHTML =
      '<div class="widget-row"><span>Estado</span><strong class="ok">' +
      (s.activo ? 'OPERATIVO' : 'OFF') +
      '</strong></div>' +
      '<div class="widget-row"><span>NGWAF Redis</span><strong class="' +
      (redisOk ? 'ok' : 'err') +
      '">' +
      (redisOk ? 'ONLINE' : 'DEGRADADO') +
      '</strong></div>' +
      '<div class="widget-row"><span>Eventos hoy</span><strong>' +
      esc(s.eventos_hoy) +
      '</strong></div>' +
      '<div class="widget-row"><span>IPs únicas hoy</span><strong>' +
      esc(s.ips_unicas_hoy) +
      '</strong></div>' +
      '<div class="widget-row"><span>Bloqueadas (WAF)</span><strong>' +
      esc(s.bloqueadas_perimetro) +
      '</strong></div>' +
      '<div class="widget-row"><span>Rate limit</span><strong>' +
      esc(s.rate_limit_max || 60) +
      ' req/min</strong></div>' +
      '<div class="widget-row"><span>Riesgo autoban</span><strong>≥' +
      esc(s.risk_autoban_umbral || 5) +
      '</strong></div>' +
      '<div class="widget-row"><span>Circuit breaker</span><strong>' +
      esc(circuitoTxt) +
      '</strong></div>';
  }

  function pintarConexiones(lista) {
    const tbody = document.getElementById('tabla-conexiones');
    if (!tbody) return;
    if (!lista.length) {
      tbody.innerHTML = '<tr><td colspan="4">Sin conexiones registradas</td></tr>';
      return;
    }
    tbody.innerHTML = lista
      .map(function (c) {
        return (
          '<tr><td><code>' +
          esc(c.ip) +
          '</code></td><td>' +
          esc(c.pais) +
          '</td><td>' +
          esc(c.isp) +
          '</td><td>' +
          esc(String(c.ultima_peticion || '').slice(0, 19)) +
          '</td></tr>'
        );
      })
      .join('');
  }

  function pintarCritico(ev) {
    const el = document.getElementById('widget-critico');
    if (!el) return;
    if (!ev) {
      el.innerHTML = '<p class="muted">No hay ataques críticos recientes.</p>';
      return;
    }
    const firma = String(ev.firma_coincidente || '').trim();
    const bloqueFirma = firma
      ? '<p class="firma-waf"><span class="badge-firma">' +
        esc(firma) +
        '</span></p>'
      : '';
    el.innerHTML =
      '<p><strong>' +
      esc(ev.tipo) +
      '</strong></p>' +
      bloqueFirma +
      '<p>IP: <code>' +
      esc(ev.ip) +
      '</code></p><p>Ruta: <code>' +
      esc(ev.ruta) +
      '</code></p><p class="muted">' +
      esc(String(ev.timestamp || '').slice(0, 19)) +
      '</p>';
  }

  /** ——— Perímetro ——— */
  async function cargarPerimetro() {
    try {
      const data = await fetchJson('/admin/api/bots-bloqueados');
      pintarBots(extraerData(data, 'bots'));
    } catch (err) {
      mostrarBanner('Error al cargar bots bloqueados: ' + err.message);
    }
  }

  function pintarBots(bots) {
    const tbody = document.getElementById('tabla-bots');
    if (!tbody) return;
    if (!bots.length) {
      tbody.innerHTML =
        '<tr><td colspan="7">No hay IPs bloqueadas por el perímetro</td></tr>';
      return;
    }
    tbody.innerHTML = bots
      .map(function (b) {
        const ttl = b.ttl_restante_seg != null
          ? Math.max(0, Math.round(Number(b.ttl_restante_seg) / 3600)) + ' h'
          : '—';
        return (
          '<tr><td><code>' +
          esc(b.ip) +
          '</code></td><td>' +
          esc(b.country) +
          '</td><td>' +
          esc(b.isp) +
          '</td><td><strong>' +
          esc(Number(b.risk_score || 0).toFixed(1)) +
          '</strong></td><td>' +
          esc(ttl) +
          '</td><td class="muted">' +
          esc(b.motivo || String(b.fecha_analisis || '').slice(0, 19) || '—') +
          '</td><td><button type="button" class="btn-whitelist" data-ip="' +
          esc(b.ip) +
          '">Desbloquear (Whitelist)</button></td></tr>'
        );
      })
      .join('');
    tbody.querySelectorAll('.btn-whitelist').forEach(function (btn) {
      btn.addEventListener('click', function () {
        whitelistIp(btn.dataset.ip, btn);
      });
    });
  }

  async function whitelistIp(ip, btn) {
    if (!ip) return;
    btn.disabled = true;
    try {
      await fetchJson('/admin/api/whitelist-ip', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip: ip }),
      });
      await cargarPerimetro();
    } catch (err) {
      mostrarBanner('No se pudo desbloquear ' + ip + ': ' + err.message);
      btn.disabled = false;
    }
  }

  /** ——— Usuarios señuelo ——— */
  function claseDepto(depto) {
    const d = String(depto || '').toUpperCase();
    if (d === 'IT') return 'badge-it';
    if (d === 'RRHH') return 'badge-rrhh';
    if (d === 'VENTAS') return 'badge-ventas';
    if (d === 'ADMIN' || d === 'ADMINISTRACIÓN') return 'badge-admin';
    return 'badge-default';
  }

  async function cargarUsuarios() {
    const tbody = document.getElementById('tabla-usuarios');
    const totalEl = document.getElementById('usuarios-total');
    if (!tbody) return;
    try {
      const data = await fetchJson('/admin/api/usuarios-senuelo');
      const lista = extraerData(data, null);
      if (totalEl) {
        totalEl.textContent = (data.total || lista.length) + ' usuario(s) en el directorio';
      }
      if (!lista.length) {
        tbody.innerHTML = '<tr><td colspan="6">No hay usuarios en la tabla señuelo</td></tr>';
        return;
      }
      tbody.innerHTML = lista
        .map(function (u) {
          const nombre = [u.nombre, u.apellido].filter(Boolean).join(' ') || '—';
          const inicial = (u.username || '?').slice(0, 2).toUpperCase();
          const depto = u.departamento || '—';
          return (
            '<tr><td>' +
            esc(u.id) +
            '</td><td><div class="user-cell"><span class="mini-avatar">' +
            esc(inicial) +
            '</span><strong>' +
            esc(u.username) +
            '</strong></div></td><td>' +
            esc(nombre) +
            '</td><td><span class="badge-depto ' +
            claseDepto(depto) +
            '">' +
            esc(depto) +
            '</span></td><td>' +
            esc(u.email || '—') +
            '</td><td>' +
            esc(u.rol || 'usuario') +
            '</td></tr>'
          );
        })
        .join('');
    } catch (err) {
      mostrarBanner('Error al cargar usuarios: ' + err.message);
      tbody.innerHTML = '<tr><td colspan="6">Error al cargar datos</td></tr>';
    }
  }

  /** ——— Reportes ——— */
  function initReportesSubtabs() {
    document.querySelectorAll('[data-subtab]').forEach(function (btn) {
      btn.addEventListener('click', function () {
        const sub = btn.dataset.subtab;
        document.querySelectorAll('[data-subtab]').forEach(function (b) {
          b.classList.toggle('active', b === btn);
        });
        document.querySelectorAll('[data-subpanel]').forEach(function (p) {
          p.classList.toggle('active', p.dataset.subpanel === sub);
        });
        if (sub === 'reportes-resumenes') cargarReportesResumenes();
      });
    });

    const form = document.getElementById('form-reportes-ip');
    if (form) {
      form.addEventListener('submit', function (e) {
        e.preventDefault();
        buscarReportes();
      });
    }
    const limpiar = document.getElementById('btn-limpiar-reportes');
    if (limpiar) {
      limpiar.addEventListener('click', function () {
        document.getElementById('input-ip-reportes').value = '';
        document.getElementById('input-fecha-inicio').value = '';
        document.getElementById('input-fecha-fin').value = '';
        document.getElementById('tabla-reportes-wrap').hidden = true;
        document.getElementById('reportes-aviso').textContent =
          'Introduce una IP o un rango de fechas para buscar.';
      });
    }
  }

  async function buscarReportes() {
    const ip = document.getElementById('input-ip-reportes').value.trim();
    const fi = document.getElementById('input-fecha-inicio').value;
    const ff = document.getElementById('input-fecha-fin').value;
    const aviso = document.getElementById('reportes-aviso');
    const wrap = document.getElementById('tabla-reportes-wrap');
    const tbody = document.getElementById('tabla-reportes');
    const params = new URLSearchParams();
    if (ip) params.set('ip', ip);
    if (fi) params.set('fecha_inicio', fi);
    if (ff) params.set('fecha_fin', ff);

    try {
      const data = await fetchJson('/admin/api/reportes-busqueda?' + params.toString());
      if (data.error_validacion) {
        aviso.textContent = data.error_validacion;
        wrap.hidden = true;
        return;
      }
      const reportes = extraerData(data, 'reportes');
      if (!reportes.length) {
        aviso.textContent = 'No se encontraron reportes para los criterios indicados.';
        wrap.hidden = true;
        return;
      }
      aviso.textContent = reportes.length + ' reporte(s) encontrado(s).';
      wrap.hidden = false;
      tbody.innerHTML = reportes
        .map(function (r) {
          return (
            '<tr><td>#' +
            esc(r.id) +
            '</td><td><code>' +
            esc(r.ip_atacante) +
            '</code></td><td>' +
            esc(String(r.fecha || '').slice(0, 19)) +
            '</td><td>' +
            (r.nis2_significativo
              ? '<span class="badge-nis2">Significativo</span>'
              : '—') +
            '</td><td><pre class="datos-reporte">' +
            esc(r.datos_ataque) +
            '</pre></td></tr>'
          );
        })
        .join('');
    } catch (err) {
      mostrarBanner('Error en búsqueda de reportes: ' + err.message);
    }
  }

  async function cargarReportesResumenes() {
    const tbody = document.getElementById('tabla-resumenes');
    if (!tbody) return;
    try {
      const data = await fetchJson('/admin/api/resumenes-panel');
      const resumenes = data.resumenes || extraerData(data, null);
      if (!resumenes.length) {
        tbody.innerHTML =
          '<tr><td colspan="4">No hay resúmenes diarios generados</td></tr>';
        return;
      }
      tbody.innerHTML = resumenes
        .map(function (r) {
          return (
            '<tr><td>' +
            esc(r.fecha) +
            '</td><td>' +
            esc(r.total_eventos) +
            '</td><td>' +
            esc(r.preview) +
            '</td><td class="muted">' +
            esc(String(r.generado_en || '').slice(0, 19)) +
            '</td></tr>'
          );
        })
        .join('');
    } catch (err) {
      mostrarBanner('Error al cargar resúmenes: ' + err.message);
      tbody.innerHTML = '<tr><td colspan="4">Error al cargar</td></tr>';
    }
  }

  /** ——— Mapa ——— */
  function initMapaLeaflet() {
    if (mapaInicializado || typeof L === 'undefined') return;
    mapaLeaflet = L.map('mapa-soc', {
      center: [20, 0],
      zoom: 2,
      minZoom: 2,
      worldCopyJump: true,
    });
    const capaOscura = L.tileLayer(
      'https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png',
      {
        attribution: '&copy; OpenStreetMap &copy; CARTO',
        subdomains: 'abcd',
        maxZoom: 19,
      }
    );
    capaOscura.addTo(mapaLeaflet);
    capaMarcadores = L.layerGroup().addTo(mapaLeaflet);
    mapaInicializado = true;

    const btn = document.getElementById('btn-recargar-mapa');
    if (btn) btn.addEventListener('click', cargarMapa);
  }

  function banderaEmoji(codigo) {
    const c = String(codigo || '').trim().toUpperCase();
    if (c.length !== 2) return '';
    return String.fromCodePoint(
      c.charCodeAt(0) + 127397,
      c.charCodeAt(1) + 127397
    );
  }

  function radioMarcador(total, esBot) {
    const t = Number(total) || 1;
    const base = Math.min(22, Math.max(8, 6 + Math.sqrt(t) * 2));
    return esBot ? base + 3 : base;
  }

  function dibujarMarcadoresMapa(atacantes) {
    if (!capaMarcadores || !mapaLeaflet) return;
    capaMarcadores.clearLayers();
    const bounds = [];
    (atacantes || []).forEach(function (a) {
      if (a.lat == null || a.lon == null) return;
      const esBot = !!a.is_bot;
      const color = esBot
        ? COLOR_MARCADOR_BOT
        : COLORES_GRAVEDAD[a.gravedad_maxima] || COLORES_GRAVEDAD.Sospechoso;
      const marcador = L.circleMarker([a.lat, a.lon], {
        radius: radioMarcador(a.total_eventos, esBot),
        fillColor: color,
        color: esBot ? '#e9d5ff' : '#ffffff',
        weight: esBot ? 3 : 2,
        opacity: 1,
        fillOpacity: esBot ? 0.95 : 0.9,
      });
      const bandera = banderaEmoji(a.pais_codigo);
      const paisTxt = (bandera ? bandera + ' ' : '') + esc(a.pais || '—');
      const ispTxt = esc(a.isp || '—');
      const cabeceraBot = esBot
        ? '<div style="color:#c084fc;font-weight:700;margin-bottom:8px">🤖 BOT BLOQUEADO - Score: ' +
          esc(Number(a.bot_score || 0).toFixed(1)) +
          '</div>'
        : '';
      marcador.bindPopup(
        '<div style="font-size:13px;line-height:1.5">' +
          cabeceraBot +
          '<strong style="color:#58a6ff">' +
          esc(a.ip) +
          '</strong><br>País: ' +
          paisTxt +
          '<br>ISP: ' +
          ispTxt +
          '<br>Eventos: ' +
          esc(a.total_eventos) +
          '<br>Severidad: ' +
          esc(a.gravedad_maxima) +
          '</div>',
        { maxWidth: 300 }
      );
      marcador.addTo(capaMarcadores);
      bounds.push([a.lat, a.lon]);
    });
    if (bounds.length > 1) {
      mapaLeaflet.fitBounds(bounds, { padding: [40, 40], maxZoom: 5 });
    } else if (bounds.length === 1) {
      mapaLeaflet.setView(bounds[0], 5);
    }
    setTimeout(function () {
      mapaLeaflet.invalidateSize({ animate: false });
    }, 200);
  }

  async function cargarMapa() {
    const estado = document.getElementById('mapa-estado');
    const banner = document.getElementById('banner-demo-mapa');
    initMapaLeaflet();
    if (estado) {
      estado.textContent = 'Cargando mapa…';
      estado.className = 'mapa-estado visible';
    }
    try {
      const json = await fetchJson('/admin/api/mapa-ips');
      const datos = json.data && json.data.atacantes != null ? json.data : json;
      document.getElementById('stat-ips').textContent = datos.total_ips ?? 0;
      document.getElementById('stat-eventos').textContent = (
        datos.total_eventos ?? 0
      ).toLocaleString('es-ES');
      const atacantes = datos.atacantes || [];
      document.getElementById('stat-marcadores').textContent = atacantes.length;
      if (banner) banner.classList.toggle('visible', !!datos.es_demo);
      dibujarMarcadoresMapa(atacantes);
      if (estado) estado.className = 'mapa-estado';
    } catch (err) {
      if (estado) {
        estado.textContent = 'Error al cargar el mapa: ' + err.message;
        estado.className = 'mapa-estado visible error';
      }
      mostrarBanner('Mapa de amenazas: ' + err.message);
    }
  }

  document.addEventListener('DOMContentLoaded', function () {
    initTabs();
    initReportesSubtabs();
  });
})();
