# vps-dashboard

Panel estático (GitHub Pages) del VPS de ZIA, en forma de diagrama de arquitectura en vivo. Inicia sesión con OIDC (código de autorización + PKCE) contra
`https://api.ziacentro.mx` con el cliente público `VpsDashboard`, llama a `GET /api/app/monitoreo-vps`
(permiso `IgasConsole.Monitoreo.VerVps`) y se refresca cada 60 s.

Sin dependencias de build: `index.html`, `app.js`, `style.css`, `config.js` (sin dependencias externas salvo la fuente JetBrains Mono).
Toda la información del servidor llega en vivo desde la API autenticada; aquí solo hay dominios públicos.
