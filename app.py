import streamlit as st
import re

# Configuración de la página
st.set_page_config(page_title="Analizador SIP Ladder", layout="wide")
st.title("📞 Analizador SIP a Diagrama de Escalera")
st.markdown("Pega tu traza de texto plano (`.txt`) de Oracle SBC, Cisco o Teams para analizar el flujo.")

# Interfaz de entrada
texto_traza = st.text_area("Traza SIP (Texto crudo):", height=250, placeholder="Pega aquí tu log SIP...")

if st.button("Analizar y Generar Diagrama", type="primary"):
    if not texto_traza.strip():
        st.warning("Por favor ingresa una traza SIP.")
    else:
        mensajes = []
        
        # Expresiones regulares
        patron_ip = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
        patron_metodo = re.compile(r'^\s*(INVITE|ACK|BYE|CANCEL|OPTIONS|REGISTER|SUBSCRIBE|NOTIFY|PRACK|UPDATE|INFO|REFER|MESSAGE)\s+sip:', re.MULTILINE)
        patron_respuesta = re.compile(r'^\s*SIP/2\.0\s+(\d{3}\s+[a-zA-Z\s]+)', re.MULTILINE)

        # Procesamiento
        bloques = texto_traza.split('\n\n')
        diagrama_mermaid = "sequenceDiagram\n"
        
        for bloque in bloques:
            ips = patron_ip.findall(bloque)
            origen = ips[0] if len(ips) > 0 else "Extremo_A"
            destino = ips[1] if len(ips) > 1 else "Extremo_B"
            
            origen_limpio = origen.replace(".", "_")
            destino_limpio = destino.replace(".", "_")
            
            evento_limpio = None
            
            match_metodo = patron_metodo.search(bloque)
            if match_metodo:
                evento_limpio = match_metodo.group(1)
                
            match_respuesta = patron_respuesta.search(bloque)
            if match_respuesta:
                 evento_limpio = match_respuesta.group(1).strip()
            
            if evento_limpio:
                diagrama_mermaid += f"    {origen_limpio}->>{destino_limpio}: {evento_limpio}\n"
                mensajes.append(evento_limpio)

        # Resultados
        if not mensajes:
            st.error("No se encontraron mensajes SIP válidos. Verifica el formato.")
        else:
            st.success(f"Análisis completado. Se procesaron {len(mensajes)} eventos.")
            
            # Columnas para organizar la vista
            col1, col2 = st.columns([1, 2])
            
            with col1:
                st.markdown("### Eventos Detectados")
                for msg in mensajes:
                    st.write(f"- {msg}")
                    
            with col2:
                st.markdown("### Diagrama de Escalera")
                # Streamlit renderiza Mermaid nativamente usando bloques de código markdown
                st.markdown(f"```mermaid\n{diagrama_mermaid}\n```")
