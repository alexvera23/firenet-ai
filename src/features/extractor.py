"""
FireNet-AI - Extractor de Características de Flujos de Red (FlowExtractor)
Basado en las especificaciones del Día 2 de docs/ROADMAP.md.

Agrega paquetes de red en flujos bidireccionales basados en 5-tuplas
(IP origen, IP destino, puerto origen, puerto destino, protocolo)
y calcula el vector de características para entrenamiento y detección en tiempo real.
"""

import time
from collections import defaultdict


class FlowExtractor:
    def __init__(self, window_seconds=2.0):
        self.window_seconds = window_seconds
        # Tabla de flujos: clave -> metadata acumulada
        self.flows = defaultdict(lambda: {
            'start_time': None,
            'last_time': None,
            'pkts_fwd': 0,
            'pkts_rev': 0,
            'bytes_fwd': 0,
            'bytes_rev': 0,
            'tcp_flags': set(),
            'src_port': 0,
            'dst_port': 0,
            'ip_version': 4,
            'protocol': 6,
            'initiator_ip': None,
            'responder_ip': None,
        })
        # Mapeo de búsqueda bidireccional: tupla ordenada -> clave canónica
        self.lookup_map = {}
        self.last_seen_time = None

    def _resolve_flow_key(self, src_ip, dst_ip, src_port, dst_port, protocol):
        """
        Determina si el paquete pertenece a un flujo existente (en dirección forward o reverse)
        o si inicia un nuevo flujo. Retorna (flow_key, is_forward).
        """
        pkt_tuple = (src_ip, dst_ip, src_port, dst_port, protocol)

        if pkt_tuple in self.lookup_map:
            return self.lookup_map[pkt_tuple]
        else:
            # Nuevo flujo iniciado por src_ip
            proto_name = "tcp" if protocol == 6 else ("udp" if protocol == 17 else f"proto_{protocol}")
            canonical_key = f"{src_ip}:{src_port}->{dst_ip}:{dst_port}/{proto_name}"
            rev_tuple = (dst_ip, src_ip, dst_port, src_port, protocol)
            
            # Registrar dirección forward para el iniciador y reverse para el receptor
            self.lookup_map[pkt_tuple] = (canonical_key, True)
            self.lookup_map[rev_tuple] = (canonical_key, False)
            return canonical_key, True

    def process_packet(self, pkt_metadata):
        """
        Procesa los metadatos de un paquete individual.
        pkt_metadata esperado:
        {
            'src_ip': str,
            'dst_ip': str,
            'src_port': int,
            'dst_port': int,
            'protocol': int,
            'ip_version': int,
            'length': int,
            'timestamp': float,
            'tcp_flags': set or list of str (opcional)
        }
        """
        src_ip = pkt_metadata['src_ip']
        dst_ip = pkt_metadata['dst_ip']
        src_port = pkt_metadata.get('src_port', 0)
        dst_port = pkt_metadata.get('dst_port', 0)
        protocol = pkt_metadata['protocol']
        now = pkt_metadata.get('timestamp', time.time())
        length = pkt_metadata.get('length', 0)

        self.last_seen_time = max(self.last_seen_time or 0, now)
        flow_key, is_forward = self._resolve_flow_key(src_ip, dst_ip, src_port, dst_port, protocol)
        flow = self.flows[flow_key]

        if flow['start_time'] is None:
            flow['start_time'] = now
            flow['src_port'] = src_port
            flow['dst_port'] = dst_port
            flow['ip_version'] = pkt_metadata.get('ip_version', 4)
            flow['protocol'] = protocol
            flow['initiator_ip'] = src_ip
            flow['responder_ip'] = dst_ip

        flow['last_time'] = now

        if is_forward:
            flow['pkts_fwd'] += 1
            flow['bytes_fwd'] += length
        else:
            flow['pkts_rev'] += 1
            flow['bytes_rev'] += length

        if 'tcp_flags' in pkt_metadata and pkt_metadata['tcp_flags']:
            flow['tcp_flags'].update(pkt_metadata['tcp_flags'])

        return flow_key

    def extract_features(self, force_all=False, current_time=None):
        """
        Calcula el vector de características para cada flujo activo o expirado.
        Retorna una lista de tuplas: (flow_key, features_dict)
        """
        dataset_rows = []
        now = current_time or self.last_seen_time or time.time()
        keys_to_remove = []

        for key, f in list(self.flows.items()):
            if f['start_time'] is None:
                continue

            duration = max(f['last_time'] - f['start_time'], 0.001)
            total_pkts = f['pkts_fwd'] + f['pkts_rev']
            total_bytes = f['bytes_fwd'] + f['bytes_rev']

            features = {
                'ip_version': f['ip_version'],
                'protocol': f['protocol'],
                'duration': round(duration, 4),
                'packets': total_pkts,
                'bytes': total_bytes,
                'pps': round(total_pkts / duration, 2),
                'bps': round((total_bytes * 8) / duration, 2),
                'pkts_fwd': f['pkts_fwd'],
                'pkts_rev': f['pkts_rev'],
                'ratio_pkts': round(f['pkts_fwd'] / max(f['pkts_rev'], 1), 4),
                'mean_pkt_size': round(total_bytes / max(total_pkts, 1), 2),
                'src_port': f['src_port'],
                'dst_port': f['dst_port'],
                'syn_flag': 1 if 'SYN' in f['tcp_flags'] else 0,
                'initiator_ip': f['initiator_ip'],
                'responder_ip': f['responder_ip'],
            }
            dataset_rows.append((key, features))

            # Limpiar flujos inactivos si superan la ventana de agregación o si force_all=True
            if force_all or (now - f['last_time'] > self.window_seconds):
                keys_to_remove.append(key)

        for k in keys_to_remove:
            if k in self.flows:
                del self.flows[k]
            # Limpiar entradas del lookup_map asociadas
            for t, val in list(self.lookup_map.items()):
                if val[0] == k:
                    del self.lookup_map[t]

        return dataset_rows
