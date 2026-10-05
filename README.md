# VT Folder Scanner

Aplicación web local en Python para seleccionar una carpeta y enviar sus
archivos a VirusTotal en lotes de hasta 4 archivos paralelos por minuto. La
clave se obtiene exclusivamente desde `.env`, nunca se envía desde el navegador
ni se guarda en el código.

## Uso

1. Instala Python 3.10 o superior.
2. Crea un entorno virtual y ejecuta `pip install -r requirements.txt`.
3. Copia `.env.example` a `.env` y añade tu API key:
   `VT_API_KEY=tu_clave_de_virustotal`.
4. Ejecuta `python app.py`.
5. Abre <http://localhost:3000> y selecciona una carpeta.

## Docker Compose

Configura primero `.env` a partir de `.env.example` y ejecuta:

```bash
docker compose up --build
```

La aplicación estará disponible en <http://localhost:3000>. El historial se
guarda en el volumen Docker `vt-history`, por lo que permanece aunque el
contenedor se recree o se reinicie. Para detenerla:

```bash
docker compose down
```

No uses `docker compose down -v` si quieres conservar el historial.

El servidor usa `POST /files`
para archivos de hasta 32 MB y obtiene primero `GET /files/upload_url` para
archivos mayores, hasta el máximo documentado de 650 MB. El límite entre
peticiones de VirusTotal se aplica en el servidor, por lo que también cubre la
petición adicional necesaria para archivos grandes.

La consulta de uso obtiene el usuario mediante `GET /users/{api-key}` y consulta
`GET /users/{user-id}/api_usage`. Las cuotas disponibles dependen del plan de
VirusTotal; el límite público documentado es 4 peticiones por minuto. Los
archivos se agrupan en lotes de cuatro y cada lote comienza una vez transcurrido
un minuto. VirusTotal puede
incorporar los archivos enviados a su dataset, por lo que no deben subirse
datos confidenciales o personales.

La aplicación guarda el historial local en `history.sqlite3` (en Docker, dentro
del volumen `vt-history`). Después de cada
subida consulta el endpoint de análisis de VirusTotal y conserva el estado
(`queued`, `in-progress`, `completed` o `failed`) y sus estadísticas de
detección. Los análisis pendientes se retoman automáticamente al volver a
iniciar la aplicación. El historial se muestra en la sección correspondiente
de la interfaz y se actualiza periódicamente.
