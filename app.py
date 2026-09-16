import streamlit as st
import re

# 1. Configuración de la página (Ancho completo para Opción C)
st.set_page_config(page_title="Analizador SIP Pro", layout="wide", initial_sidebar_state="expanded")

# --- LÓGICA DE PARSEO Y DIAGNÓSTICO ---
def procesar_traza(texto_traza):
    mensajes = []
    errores_encontrados = []
    call_ids = set()
    
    # Regex blindados para evitar capturar saltos de línea (como el problema del 'Via')
    patron_ip = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
    # Solo busca métodos al inicio de la línea
    patron_metodo = re.compile(r'^(INVITE|ACK|BYE|CANCEL|OPTIONS|REGISTER|SUBSCRIBE|NOTIFY|PRACK|UPDATE|INFO|REFER|MESSAGE)\b', re.MULTILINE)
    # Atrapa respuestas pero se detiene estrictamente antes del salto de línea [^\r\n]+
    patron_respuesta = re.compile(r'^SIP/2\.0\s+(\d{3}\s+[^\r\n]+)', re.MULTILINE)
    # Extraer Call-IDs reales
    patron_call_id = re.compile(r'^Call-ID:\s*([^\r\n]+)', re.IGNORECASE | re.MULTILINE)

    bloques = texto_traza.strip().split('\n\n')
    
    # autonumber enumera las flechas automáticamente
    diagrama_mermaid = "sequenceDiagram\n    autonumber\n"
    
    for bloque in bloques:
        if not bloque.strip(): continue
        
        ips = patron_ip.findall(bloque)
        origen = ips[0] if len(ips) > 0 else "Origen"
        destino = ips[1] if len(ips) > 1 else "Destino"
        
        # Buscar Call-ID en el bloque
        cid_match = patron_call_id.search(bloque)
        if cid_match: call_ids.add(cid_match.group(1).strip())
        
        evento_limpio = None
        es_error = False
        
        match_metodo = patron_metodo.search(bloque)
        if match_metodo:
            evento_limpio = match_metodo.group(1).strip()
            
        match_respuesta = patron_respuesta.search(bloque)
        if match_respuesta:
            evento_limpio = match_respuesta.group(1).strip()
            # Detectar si es un código de error SIP (4xx, 5xx, 6xx)
            if evento_limpio.startswith(('4', '5', '6')):
                es_error = True
                errores_encontrados.append(evento_limpio)
        
        if evento_limpio:
            # Las comillas dobles "" alrededor de las IPs evitan que Mermaid colapse
            if es_error:
                # Flecha cruzada (--x) para errores
                diagrama_mermaid += f'    "{origen}"--x"{destino}": {evento_limpio}\n'
            else:
                # Flecha normal
                diagrama_mermaid += f'    "{origen}"->>"{destino}": {evento_limpio}\n'
                
            mensajes.append({"origen": origen, "destino": destino, "evento": evento_limpio})

    return mensajes, diagrama_mermaid, errores_encontrados, list(call_ids)

# --- INTERFAZ UI (DASHBOARD OPCIÓN C) ---

# Panel Lateral (Sidebar)
st.sidebar.title("⚙️ Entrada de Datos")
st.sidebar.markdown("Pega trazas de Session Border Controllers, Cisco CUBE o gateways locales.")
texto_traza = st.sidebar.text_area("Log de Señalización:", height=400, placeholder="PRACK sip:172.17...\nVia: SIP/2.0/UDP...")
btn_analizar = st.sidebar.button("Analizar Traza", type="primary", use_container_width=True)

# Panel Principal
st.title("📊 Dashboard de Diagnóstico SIP")

if btn_analizar and texto_traza:
    mensajes, diagrama, errores, call_ids = procesar_traza(texto_traza)
    
    if not mensajes:
        st.error("No se detectó señalización válida. Asegúrate de que los mensajes SIP estén separados por un renglón en blanco (salto de línea).")
    else:
        # 1. TARJETAS DE MÉTRICAS TOP
        col1, col2, col3, col4 = st.columns(4)
        col1.metric("Mensajes Procesados", len(mensajes))
        col2.metric("Nodos Detectados", len(set([m['origen'] for m in mensajes] + [m['destino'] for m in mensajes])))
        col3.metric("Fallas (4xx-6xx)", len(errores))
        col4.metric("Call-IDs Únicos", len(call_ids))

        st.divider()

        # 2. PANEL DIVIDIDO: Diagrama y Análisis
        col_diag, col_analisis = st.columns([3, 2])
        
        with col_diag:
            st.subheader("Secuencia (Ladder Diagram)")
            st.markdown(f"```mermaid\n{diagrama}\n```")
            
        with col_analisis:
            st.subheader("🧠 Motor de Diagnóstico")
            
            # Evaluación automática de errores
            if errores:
                st.error(f"**ALERTA:** Se detectaron {len(errores)} mensajes de rechazo o falla.")
                for err in set(errores):
                    st.write(f"❌ `{err}`")
                    
                st.markdown("### 💡 Sugerencias de Solución:")
                # Base de conocimiento simulada
                if any("403" in e for e in errores) or any("401" in e for e in errores):
                    st.info("**Autenticación / ACL:** Falla de permisos. Verifica las reglas HMR, listas de acceso (ACL) o si la IP de origen está permitida en el entorno.")
                if any("488" in e for e in errores):
                    st.info("**Negociación SDP:** Incompatibilidad de codecs. Revisa si un extremo exige G.729 y el otro solo envía G.711, o problemas con el ptime.")
                if any("503" in e for e in errores):
                    st.info("**Saturación / Enrutamiento:** Destino inalcanzable. Revisa políticas de ruteo de voz, estado de las troncales SIP o capacidades concurrentes máximas.")
                if any("487" in e for e in errores):
                    st.info("**Request Terminated:** El origen canceló la llamada antes de que fuera contestada (comportamiento normal si el usuario cuelga antes de tiempo).")
            else:
                st.success("✅ El flujo parece estable. No se detectaron códigos de falla (4xx, 5xx, 6xx).")
                
            st.divider()
            
            st.markdown("### Metadatos Extraídos")
            if call_ids:
                st.write("**Call-IDs implicados en esta traza:**")
                for cid in call_ids:
                    st.code(cid)
            
elif not texto_traza:
    st.info("👈 Pega tu texto crudo en el panel lateral izquierdo y haz clic en 'Analizar' para ver la magia.")
