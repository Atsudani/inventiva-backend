// ============================================
// BACKEND: Tipos para permisos
// src/auth/types/permisos.types.ts (crear esta carpeta y archivo)
// ============================================

export interface PermisosAccion {
  ver: boolean;
  crear: boolean;
  editar: boolean;
  eliminar: boolean;
}

export interface Pagina {
  id: number;
  codigo: string;
  nombre: string;
  ruta: string;
  icono: string | null;
  orden: number;
  permisos: PermisosAccion;
}

export interface Tipo {
  id: number;
  codigo: string;
  nombre: string;
  orden: number;
  paginas: Pagina[];
}

export interface Modulo {
  id: number;
  codigo: string;
  nombre: string;
  icono: string;
  orden: number;
  tipos: Tipo[];
}

export type PermisosJerarquicos = Modulo[];

// Tipos internos para el procesamiento (no se exportan al frontend)
export interface PaginaIntermedia {
  id: number;
  codigo: string;
  nombre: string;
  ruta: string;
  icono: string | null;
  orden: number;
  permisos: PermisosAccion;
}

export interface TipoIntermedio {
  id: number;
  codigo: string;
  nombre: string;
  icono: string;
  orden: number;
  paginas: PaginaIntermedia[];
}

export interface ModuloIntermedio {
  id: number;
  codigo: string;
  nombre: string;
  icono: string;
  orden: number;
  tipos: Map<number, TipoIntermedio>;
}
