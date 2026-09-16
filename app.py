import streamlit as st
import re
import tempfile
import os
import asyncio
import pyshark

# 1. Configuración de página
st.set_page_config(page_title="Analizador SIP Pro", layout="wide", initial_sidebar_state="expanded")

# 2. INYECCIÓN DE CSS
estilo_css = """
<style>
    .stApp { background-color: #f8f9fa; }
    div[data-testid="metric-container"] {
        background-color: white; border: 1px solid #e1e4e8; padding: 15px 20px;
        border-radius: 10px; box-shadow: 0 4px 6px rgba(0,0,0,0.05); transition: transform 0.2s;
    }
    div[data-testid="metric-container"]:hover { transform: translateY(-5px); box-shadow: 0 6px 12px rgba(0,0,0,0.1); }
    .sip-badge { display: inline-block; padding: 4px 10px; border-radius: 15px; font-size: 13px; font-weight: 600; margin-bottom: 5px; }
    .sip-method { background-color: #e0e7ff; color: #3730a3; border: 1px solid #c7d2fe; } 
    .sip-1xx { background-color: #f3f4f6; color: #4b5563; border: 1px solid #e5e7eb; }    
    .sip-2xx { background-color: #dcfce7; color: #166534; border: 1px solid #bbf7d0; }    
    .sip-error { background-color: #fee2e2; color: #991b1b; border: 1px solid #fecaca; }  
    .timeline-event {
        background: white; border-left: 4px solid #6366f1; padding: 10px 15px;
        margin-bottom: 10px; border-radius: 0 8px 8px 0; box-shadow: 0 2px 4px rgba(0,0,0,0.03);
        font-family: monospace; font-size: 14px; color: #333;
    }
</style>
"""
st.markdown(estilo_css, unsafe_allow_html=True)

# 3. FUNCIONES AUXILIARES Y DE PARSEO
def determinar_clase_sip(evento):
    if not evento: return 'sip-method'
    if evento[0] == '1': return 'sip-1xx'
    if evento[0] == '2': return 'sip-2xx'
    if evento[0] in ['3', '4', '5', '6']: return 'sip-error'
    return 'sip-method'

def procesar_txt(texto_traza):
    mensajes, errores_encontrados, call_ids = [], [], set()
    patron_ip = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
    patron_metodo = re.compile(r'^(INVITE|ACK|BYE|CANCEL|OPTIONS|REGISTER|SUBSCRIBE|NOTIFY|PRACK|UPDATE|INFO|REFER|MESSAGE)\b', re.MULTILINE)
    patron_respuesta = re.compile(r'^SIP/2\.0\s+(\d{3}\s+[^\r\n]+)', re.MULTILINE)
    patron_call_id = re.compile(r'^Call-ID:\s*([^\r\n]+)', re.IGNORECASE | re.MULTILINE)

    bloques = texto_traza.strip().split('\n\n')
    diagrama_mermaid = "sequenceDiagram\n    autonumber\n"
    
    for bloque in bloques:
        if not bloque.strip(): continue
        ips = patron_ip.findall(bloque)
        origen = ips[0] if len(ips) > 0 else "Origen"
        destino = ips[1] if len(ips) > 1 else "Destino"
        
        cid_match = patron_call_id.search(bloque)
        if cid_match: call_ids.add(cid_match.group(1).strip())
        
        evento_limpio, es_error = None, False
        match_metodo = patron_metodo.search(bloque)
        if match_metodo: evento_limpio = match_metodo.group(1).strip()
            
        match_respuesta = patron_respuesta.search(bloque)
        if match_respuesta:
            evento_limpio = match_respuesta.group(1).strip()
            if evento_limpio.startswith(('4', '5', '6')):
                es_error, errores_encontrados.append(evento_limpio) = True, None
        
        if evento_limpio:
            diagrama_mermaid += f'    "{origen}"--x"{destino}": {evento_limpio}\n' if es_error else f'    "{origen}"->>"{destino}": {evento_limpio}\n'
            mensajes.append({"origen": origen, "destino": destino, "evento": evento_limpio, "clase": determinar_clase_sip(evento_limpio)})

    return mensajes, diagrama_mermaid, errores_encontrados, list(call_ids)

def procesar_pcap(archivo_subido):
    # Parche para asincronía en Streamlit
    asyncio.set_event_loop(asyncio.new_event_loop())
    
    mensajes, errores_encontrados, call_ids = [], [], set()
    diagrama_mermaid = "sequenceDiagram\n    autonumber\n"
    
    # Guardar archivo temporalmente para que pyshark pueda leerlo
    with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as tmp:
        tmp.write(archivo_subido.getvalue())
        tmp_path = tmp.name

    try:
        # display_filter='sip' hace que solo lea los paquetes relevantes, siendo mucho más rápido
        captura = pyshark.FileCapture(tmp_path, display_filter='sip')
        for paquete in captura:
            if hasattr(paquete, 'sip'):
                origen = paquete.ip.src
                destino = paquete.ip.dst
                evento_limpio, es_error = None, False
                
                # Buscar Call-ID
                if hasattr(paquete.sip, 'Call-ID'):
                    call_ids.add(paquete.sip.get_field_value('Call-ID'))
                
                # Identificar si es Request o Response
                if hasattr(paquete.sip, 'Method'):
                    evento_limpio = paquete.sip.get_field_value('Method')
                elif hasattr(paquete.sip, 'Status-Code'):
                    codigo = paquete.sip.get_field_value('Status-Code')
                    # Intentar obtener la frase (ej. "OK" o "Not Found")
                    frase = paquete.sip.get_field_value('Status-Line').split(' ', 2)[-1] if hasattr(paquete.sip, 'Status-Line') else ""
                    evento_limpio = f"{codigo} {frase}".strip()
                    if str(codigo).startswith(('4', '5', '6')):
                        es_error = True
                        errores_encontrados.append(evento_limpio)
                
                if evento_limpio:
                    diagrama_mermaid += f'    "{origen}"--x"{destino}": {evento_limpio}\n' if es_error else f'    "{origen}"->>"{destino}": {evento_limpio}\n'
                    mensajes.append({"origen": origen, "destino": destino, "evento": evento_limpio, "clase": determinar_clase_sip(evento_limpio)})
        captura.close()
    finally:
        os.remove(tmp_path) # Limpieza del archivo temporal
        
    return mensajes, diagrama_mermaid, errores_encontrados, list(call_ids)

# --- PANEL LATERAL ---
st.sidebar.title("⚙️ Entrada de Datos")
st.sidebar.markdown("Sube un archivo **.pcap / .txt** o pega el texto plano.")

archivo_cargado = st.sidebar.file_uploader("Subir Archivo de Traza", type=['txt', 'pcap', 'pcapng'])
texto_traza = st.sidebar.text_area("O pega el texto crudo:", height=200, placeholder="Pega tu traza aquí...")

btn_analizar = st.sidebar.button("⚡ Analizar Traza", type="primary", use_container_width=True)

# --- PANEL PRINCIPAL ---
st.title("📊 Dashboard Analizador SIP Pro")

if btn_analizar:
    mensajes, diagrama, errores, call_ids = None, None, None, None
    
    if archivo_cargado is not None:
        # Analizar según el tipo de archivo subido
        extension = archivo_cargado.name.split('.')[-1].lower()
        with st.spinner("Procesando archivo, esto puede tomar unos segundos..."):
            if extension in ['pcap', 'pcapng']:
                mensajes, diagrama, errores, call_ids = procesar_pcap(archivo_cargado)
            elif extension == 'txt':
                # Leer texto del archivo subido
                texto_decodificado = archivo_cargado.getvalue().decode("utf-8")
                mensajes, diagrama, errores, call_ids = procesar_txt(texto_decodificado)
    elif texto_traza:
        mensajes, diagrama, errores, call_ids = procesar_txt(texto_traza)
    else:
        st.warning("Por favor, sube un archivo o pega el texto de la traza para comenzar.")
        st.stop()
        
    if not mensajes:
        st.error("No se detectó señalización SIP válida. Revisa tu archivo o texto.")
    else:
        # --- RENDERIZADO DEL DASHBOARD ---
        col1, col2, col3, col4 = st.columns(4)
        col1.metric("Mensajes Totales", len(mensajes))
        col2.metric("Nodos Detectados", len(set([m['origen'] for m in mensajes] + [m['destino'] for m in mensajes])))
        col3.metric("Fallas (4xx-6xx)", len(errores), delta="-Crítico" if errores else "OK", delta_color="inverse")
        col4.metric("Call-IDs", len(call_ids))

        st.markdown("<br>", unsafe_allow_html=True)
        col_diag, col_eventos = st.columns([3, 2])
        
        with col_diag:
            st.subheader("Flujo de Señalización (Ladder)")
            st.markdown(f"```mermaid\n{diagrama}\n```")
            
        with col_eventos:
            st.subheader("📄 Timeline Dinámico")
            html_eventos = ""
            for msg in mensajes:
                html_eventos += f"""
                <div class="timeline-event">
                    <span class="sip-badge {msg['clase']}">{msg['evento']}</span><br>
                    <span style="font-size: 12px; color: #666;">
                        <strong>De:</strong> {msg['origen']} &rarr; <strong>A:</strong> {msg['destino']}
                    </span>
                </div>
                """
            st.markdown(html_eventos, unsafe_allow_html=True)
            
            st.divider()
            if errores:
                st.error("⚠️ **Se detectaron errores en la sesión:**")
                for err in set(errores):
                    st.write(f"❌ {err}")
            else:
                st.success("✅ Flujo SIP completado sin errores aparentes.")
                
else:
    st.info("👈 Utiliza el panel lateral para subir un archivo PCAP/TXT o pegar tu log, y haz clic en Analizar.")
