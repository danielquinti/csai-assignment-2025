-- 1. Tabla de Usuarios (Con el rol integrado)
CREATE TABLE usuarios (
    id INT PRIMARY KEY AUTO_INCREMENT, -- O SERIAL en Postgres
    email VARCHAR(100) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    rol VARCHAR(20) NOT NULL DEFAULT 'cliente' -- Por defecto todos son clientes
);

-- 2. Tabla de Productos (Independiente)
CREATE TABLE productos (
    id INT PRIMARY KEY AUTO_INCREMENT,
    nombre VARCHAR(100) NOT NULL,
    precio DECIMAL(10, 2) NOT NULL,
    descripcion TEXT
);