Verbo HTTP,Ruta (Endpoint),Rol Permitido,Acción (Descripción)
GET,/api/productos,Todos (Admin y Cliente),Obtiene la lista completa de productos.
GET,/api/productos/:id,Todos (Admin y Cliente),Obtiene el detalle de un solo producto por su ID.
POST,/api/productos,Solo Admin,Crea un nuevo producto en la base de datos.
PUT,/api/productos/:id,Solo Admin,Actualiza/Modifica los datos de un producto existente.
DELETE,/api/productos/:id,Solo Admin,Elimina un producto de la base de datos.