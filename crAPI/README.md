# crAPI Security Audit & Vulnerability Report

Este repositorio documenta una auditoría de seguridad realizada sobre **crAPI (Completely Ridiculous API)**, una aplicación web intencionalmente vulnerable basada en el **OWASP API Top 10**, diseñada para la práctica de pruebas de penetración en APIs.

---

## ⚠️ Disclaimer Legal

> Este laboratorio y este informe tienen fines puramente educativos y de investigación en seguridad ofensiva. **No intente explotar estas vulnerabilidades en sistemas de producción sin autorización explícita.** El acceso no autorizado a sistemas informáticos es ilegal.

---

## 📋 Tabla de Contenidos

1. [Resumen Ejecutivo](#-resumen-ejecutivo)
2. [Metodología](#-metodología)
3. [Hallazgos Técnicos (Vulnerabilidades)](#-hallazgos-técnicos-vulnerabilidades)
   * [IDOR / BOLA en Módulo de Órdenes](#1-idor--bola-en-módulo-de-órdenes)
   * [NoSQLi en Validación de Cupones](#2-nosqli-en-validación-de-cupones)
   * [BOLA Enlazada y Control de Estados en Servicios](#3-bola-enlazada-y-control-de-estados-en-servicios)
   * [Subida Insegura de Archivos en Perfil](#4-subida-insegura-de-archivos-en-perfil)
4. [Recomendaciones Generales de Mitigación](#-recomendaciones-generales-de-mitigación)

---

## 📢 Resumen Ejecutivo

La auditoría de seguridad sobre crAPI identificó fallos críticos que comprometen la autorización, la validación de entradas y el manejo de archivos. Mediante técnicas de intercepción de tráfico y manipulación de parámetros, se logró acceder a datos financieros, extraer información de identificación vehicular (VINs) ajenos y auditar el flujo transaccional de otros usuarios.

| ID | Vulnerabilidad | Severidad | OWASP API Top 10 |
|:---|:---|:---|:---|
| 01 | Broken Object Level Authorization (BOLA) | Crítica | API1:2023 |
| 02 | NoSQL Injection (NoSQLi) | Alta | API3:2023 |
| 03 | BOLA Enlazada y Control de Estados | Crítica | API1:2023 |
| 04 | Unrestricted File Upload | Alta | API6:2023 |

---

## 🛠️ Metodología

La evaluación se realizó bajo un enfoque de caja negra (*black-box*):
1. **Despliegue del Laboratorio:** Instalación de crAPI mediante contenedores Docker locales.
2. **Intercepción de Tráfico:** Uso de **Burp Suite** para capturar, modificar y reinyectar peticiones HTTP entre el cliente y el servidor.
3. **Análisis de Endpoints:** Mapeo de la API para identificar fallos lógicos en la autorización y el procesamiento de datos.

---

## 🔍 Hallazgos Técnicos (Vulnerabilidades)

### 1. IDOR / BOLA en Módulo de Órdenes

**Descripción:** El endpoint encargado de recuperar los detalles de una orden carece de validación de propiedad, permitiendo a cualquier usuario autenticado consultar transacciones ajenas mediante la alteración secuencial de identificadores.

* **Endpoint Vulnerable:** `GET /shop/api/v2/order/order_id`
* **Severidad:** Crítica

#### Pasos de Explotación:
1. Capturar la petición legítima de una orden propia en Burp Suite.
2. Modificar el parámetro `order_id` en la URL (ej. cambiar a `1`, `2` o `3`).
3. El servidor responde con un código `200 OK` devolviendo los detalles financieros, artículos y datos personales asociados a la orden de otro usuario.

> **PoC:**
> ```http
> GET /shop/api/v2/order/2 HTTP/1.1
> Host: localhost:8888
> Authorization: Bearer <TOKEN_VALIDO>
> ```

#### Remedición:
Implementar una validación en el backend que compare el `user_id` extraído del token JWT con el propietario registrado de la `order_id` solicitada antes de entregar la información.

---

### 2. NoSQLi en Validación de Cupones

**Descripción:** El endpoint de validación de cupones concatena de forma insegura la entrada del usuario en una consulta de MongoDB, permitiendo el uso de operadores lógicos para manipular la lógica de negocio.

* **Endpoint Vulnerable:** `POST /community/api/v2/coupon/validate-coupon`
* **Severidad:** Alta

#### Pasos de Explotación:
1. Interceptar la petición de validación de cupones en la tienda.
2. Enviar un payload JSON utilizando operadores de desigualdad NoSQL como `$ne`.

> **PoC (Payload):**
> ```json
> {
>   "coupon_code": {
>     "$ne": "INEXISTENTE"
>   }
> }
> ```
> El servidor procesa la consulta y revela códigos de descuento válidos (ej. `TRAC075`).

#### Remedición:
Aplicar esquemas estrictos de validación de tipos de datos en la entrada del usuario y utilizar consultas parametrizadas que desarmen la interpretación de operadores lógicos.

---

### 3. BOLA Enlazada y Control de Estados en Servicios

**Descripción:** Esta vulnerabilidad combina la exposición masiva de datos en los reportes de taller con fallos de control de acceso en los tableros de control. Dado que el endpoint de reportes expone de forma directa listas y VINs de manera masiva, el uso posterior del parámetro VIN en el dashboard sirve principalmente para **auditar y consultar el estado transaccional (Business Logic State Control)** de las reparaciones de otros usuarios.

#### Paso 1: Extracción Masiva de Registros y VINs
* **Endpoint Vulnerable:** `GET /crAPI/api/v2/service-report?id={{report_id}}`
* La enumeración secuencial de reportes expone notas de taller y VINs.

#### Paso 2: Auditoría del Estado Transaccional en el Dashboard
* **Endpoint Objetivo:** `GET /vehicle-service-dashboard?VIN={{vin_ajeno}}`
* Al inyectar el VIN recolectado en la ruta del dashboard, el sistema omite la validación de propiedad y expone el estatus operativo del servicio (por ejemplo, permitiendo verificar si la orden se encuentra *pendiente*, *aprobada* o *cancelada*).

> **PoC:**
> Al consultar el dashboard pasando un VIN obtenido de un reporte ajeno, la interfaz expone el estado transaccional del servicio y los metadatos correspondientes de un tercero.

#### Remedición:
Validar estrictamente en el backend que el usuario autenticado posea una relación de propiedad directa con el VIN consultado antes de renderizar los estados del servicio, flujos de aprobación o telemetría en el dashboard.

---

### 4. Subida Insegura de Archivos en Perfil

**Descripción:** La funcionalidad de carga multimedia en el perfil de usuario (`/my-profile`) no valida adecuadamente el tipo MIME ni restringe las extensiones de archivos, permitiendo subir código ejecutable o scripts personalizados.

* **Endpoint Vulnerable:** `POST /identity/api/v2/user/videos`
* **Severidad:** Alta

#### Pasos de Explotación:
1. En la sección de perfil, seleccionar un archivo de texto o script con extensión `.py` para subirlo como video.
2. La API acepta el archivo con un código `200 OK` y almacena el recurso.
3. Al intentar renderizarlo, el reproductor multimedia del frontend falla al decodificar texto plano como si fuera un contenedor de video, evidenciando ausencia de sanitización y abriendo un vector potencial para procesamiento inseguro de librerías en backend (como conversiones automáticas a Base64 o manipulación de archivos).

> **Respuesta del Servidor:**
> ```json
> {"id":6,"video_name":"debian2.py","conversion_params":"-v codec h264","profileVideo":"data:image/jpeg;base64,..."}
> ```

#### Remedición:
1. Implementar una lista blanca (*whitelist*) estricta de extensiones permitidas y validar el tipo MIME real del archivo utilizando librerías de verificación binaria en el servidor.
2. Almacenar los archivos subidos en volúmenes o buckets aislados, renombrándolos de forma aleatoria (con UUIDs) y deshabilitando la ejecución de scripts en dichos directorios.

---

## 🏁 Recomendaciones Generales de Mitigación

* **Principio de Mínimo Privilegio:** Ninguna entidad debe poder acceder a recursos de objetos ni consultar estados transaccionales sin una validación explícita de control de acceso basada en roles y propiedad (mitigación de BOLA).
* **Sanitización de Entradas:** Tratar toda entrada del cliente (parámetros de URL, cuerpos JSON, archivos multipart) como no confiable.
* **Cabeceras de Seguridad:** Mantener configuradas directivas robustas en el proxy inverso (como OpenResty/Nginx) para evitar interpretaciones erróneas de tipos de contenido en el navegador.
