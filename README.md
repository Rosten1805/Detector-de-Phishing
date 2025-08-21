# Detector de Phishing (Cliente)

https://detector-de-phishing.netlify.app/

Se realiza una herramienta para analizar correos electrónicos y capturas sospechosas **100% en el navegador**, sin subir datos a servidores externos. Permite detectar posibles fraudes mediante OCR, análisis de URLs, dominios y palabras de urgencia.

---

## Descripción

Este proyecto es un detector de phishing que funciona completamente local en tu navegador. Puedes:

- Analizar **imágenes** de correos electrónicos mediante OCR.
- Leer texto de **PDFs** y archivos de texto (`.txt` y `.eml`).
- Detectar dominios sospechosos, acortadores de URLs y posibles homógrafos.
- Evaluar **palabras de urgencia** o manipulación que suelen aparecer en ataques de phishing.
- Estimar un **nivel de riesgo heurístico** para el correo analizado.

> Esta herramienta es educativa. No reemplaza sistemas profesionales de seguridad. No puede validar SPF/DKIM/DMARC desde una captura.

---

## Funcionalidades

1. **Subida de archivos**  
   - Imágenes: `JPG`, `JPEG`, `PNG`, `WEBP`  
   - Documentos: `PDF`  
   - Texto: `TXT`, `EML`  

2. **OCR para imágenes**  
   - Detecta texto en imágenes de correos.
   - Soporta español e inglés.

3. **Análisis de URLs y dominios**  
   - Detecta TLDs sospechosos (`.xyz`, `.top`, `.ru`, etc.).
   - Identifica acortadores de enlaces (`bit.ly`, `t.co`, etc.).
   - Reconoce dominios en Punycode/IDN y posibles homógrafos.

4. **Detección de lenguaje urgente o manipulador**  
   - Palabras clave en inglés y español como "urgente", "bloqueado", "verify", "password", etc.

5. **Riesgo heurístico**  
   - Calcula un puntaje de riesgo del 0 al 100 basado en heurísticas.
   - Muestra detalles y hallazgos por categoría: `ok`, `warn`, `bad`.

---

## Tecnologías utilizadas

- HTML, CSS y JavaScript puro (sin backend)
- [PDF.js](https://mozilla.github.io/pdf.js/) – Lectura de PDFs
- [Tesseract.js](https://tesseract.projectnaptha.com/) – OCR de imágenes
- [Punycode.js](https://github.com/bestiejs/punycode.js/) – Decodificación de dominios IDN

<img width="1090" height="829" alt="image" src="https://github.com/user-attachments/assets/fdcaad93-aaa2-4425-945e-f2e236b8f6b6" />

