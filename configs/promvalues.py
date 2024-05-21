class PrometheusValues:
    
    def __init__(self):
        pass

    def get_promxy_values(self, wrkspc_id):
        return {
                "serviceAccount": {
                    "create": True,
                    "annotations": {
                        "eks.amazonaws.com/role-arn": "arn:aws:iam::008543762315:role/amp-iamproxy-query-role"
                    },
                    "name": "amp-iamproxy-query-service-account"
                },
                "ingress": {
                    "enabled": False
                },
                "ingress_alb": {
                    "enabled": True,
                    "annotations": {
                        "kubernetes.io/ingress.class": "alb",
                        "alb.ingress.kubernetes.io/scheme": "internet-facing",
                        "alb.ingress.kubernetes.io/target-type": "ip"
                    },
                    "path": "/",
                    "service": {
                        "name": "ingress-nginx-service",
                        "port": 80
                    }
                },
                "ingress_nginx": {
                    "enabled": True,
                    "annotations": {
                        "nginx.ingress.kubernetes.io/auth-type": "basic",
                        "nginx.ingress.kubernetes.io/auth-secret": "basic-auth",
                        "nginx.ingress.kubernetes.io/auth-realm": "Authentication Required - promxy",
                        "nginx.ingress.kubernetes.io/enable-cors": "true",
                        "nginx.ingress.kubernetes.io/cors-allow-headers": "Authorization, origin, accept"
                    },
                    "path": "/",
                    "service": {
                        "name": "ingress-promxy",
                        "port": 8082
                    }
                },
                "server": {
                    "sidecareContainers": [
                        {
                            "name": "aws-sigv4-proxy-sidecar",
                            "image": "public.ecr.aws/aws-observability/aws-sigv4-proxy:v1.0.1",
                            "args": [
                                "--name",
                                "aps",
                                "--region",
                                "us-east-1",
                                "--host",
                                "aps-workspaces.us-east-1.amazonaws.com",
                                "--port",
                                ":8005"
                            ],
                            "ports": [
                                {
                                    "name": "aws-sigv4-proxy",
                                    "containerPort": 8005
                                }
                            ]
                        }
                    ]
                },
                "config": {
                    "promxy": {
                        "server_groups": [
                            {
                                "static_configs": [
                                    {
                                        "targets": [
                                            "localhost:8005"
                                        ]
                                    }
                                ],
                                "path_prefix": f"workspaces/{wrkspc_id}",
                                "labels": {
                                    "prom_workspace": "workspace_1"
                                }
                            }
                        ]
                    }
                }
            }        

  
    def get_prom_values(self, prom_ingestrole_arn, region, wrkspc_id):
        return {
                "alertmanager": {
                "persistentVolume": {
                "enabled": False
                    }
                },
                "serviceAccounts": {
                    "server": {
                    "name": "amp-iamproxy-ingest-service-account",
                    "annotations": { 
                        "eks.amazonaws.com/role-arn": f"{prom_ingestrole_arn}"
                        }
                    }
                },               
                "server": {
                    "fullnameOverride": "prometheus-server",
                    "persistentVolume": {"enabled": False},
                    "remoteWrite": [{
                      "url": f"https://aps-workspaces.{region}.amazonaws.com/workspaces/{wrkspc_id}/api/v1/remote_write",
                      "sigv4": {
                          "region": f"{region}",
                          "access_key": "AKIAQD7J7O6FVDNJGXDL",
                          "secret_key": "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"
                          #   "role_arn": f"{prom_ingestrole_arn}"
                      },
                      "queue_config": {
                         "max_samples_per_send": 1000,
                         "max_shards": 200,
                         "capacity": 2500
                    }
                 }
                ],
            },               
                "serverFiles": {
                    "prometheus.yml": {
                        "scrape_configs": [
                            {
                                "job_name": "prometheus",
                                "static_configs": [
                                    {
                                        "targets": [
                                            "localhost:9090"
                                        ]
                                    }
                                ]
                            },
                            {
                                "job_name": "kubernetes-apiservers",
                                "kubernetes_sd_configs": [
                                    {
                                        "role": "endpoints"
                                    }
                                ],
                                "scheme": "https",
                                "tls_config": {
                                    "ca_file": "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt",
                                    "insecure_skip_verify": True
                                },
                                "bearer_token_file": "/var/run/secrets/kubernetes.io/serviceaccount/token",
                                "relabel_configs": [
                                    {
                                        "source_labels": [
                                            "__meta_kubernetes_namespace",
                                            "__meta_kubernetes_service_name",
                                            "__meta_kubernetes_endpoint_port_name"
                                        ],
                                        "action": "keep",
                                        "regex": "default;kubernetes;https"
                                    }
                                ]
                            },
                            {
                                "job_name": "kubernetes-nodes",
                                "scheme": "https",
                                "tls_config": {
                                    "ca_file": "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt",
                                    "insecure_skip_verify": True
                                },
                                "bearer_token_file": "/var/run/secrets/kubernetes.io/serviceaccount/token",
                                "kubernetes_sd_configs": [
                                    {
                                        "role": "node"
                                    }
                                ],
                                "relabel_configs": [
                                    {
                                        "action": "labelmap",
                                        "regex": "__meta_kubernetes_node_label_(.+)"
                                    },
                                    {
                                        "target_label": "__address__",
                                        "replacement": "kubernetes.default.svc:443"
                                    },
                                    {
                                        "source_labels": [
                                            "__meta_kubernetes_node_name"
                                        ],
                                        "regex": "(.+)",
                                        "target_label": "__metrics_path__",
                                        "replacement": "/api/v1/nodes/$1/proxy/metrics"
                                    }
                                ]
                            },
                            {
                                "job_name": "kubernetes-nodes-cadvisor",
                                "scrape_interval": "10s",
                                "scrape_timeout": "10s",
                                "scheme": "https",
                                "tls_config": {
                                    "ca_file": "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
                                },
                                "bearer_token_file": "/var/run/secrets/kubernetes.io/serviceaccount/token",
                                "kubernetes_sd_configs": [
                                    {
                                        "role": "node"
                                    }
                                ],
                                "relabel_configs": [
                                    {
                                        "action": "labelmap",
                                        "regex": "__meta_kubernetes_node_label_(.+)"
                                    },
                                    {
                                        "target_label": "__address__",
                                        "replacement": "kubernetes.default.svc:443"
                                    },
                                    {
                                        "source_labels": [
                                            "__meta_kubernetes_node_name"
                                        ],
                                        "regex": "(.+)",
                                        "target_label": "__metrics_path__",
                                        "replacement": "/api/v1/nodes/${1}/proxy/metrics/cadvisor"
                                    }
                                ],
                                "metric_relabel_configs": [
                                    {
                                        "action": "replace",
                                        "source_labels": [
                                            "id"
                                        ],
                                        "regex": "^/machine\\.slice/machine-rkt\\\\x2d([^\\\\]+)\\\\.+/([^/]+)\\.service$",
                                        "target_label": "rkt_container_name",
                                        "replacement": "${2}-${1}"
                                    },
                                    {
                                        "action": "replace",
                                        "source_labels": [
                                            "id"
                                        ],
                                        "regex": "^/system\\.slice/(.+)\\.service$",
                                        "target_label": "systemd_service_name",
                                        "replacement": "${1}"
                                    }
                                ]
                            },
                            {
                                "job_name": "kubernetes-service-endpoints",
                                "honor_labels": True,
                                "kubernetes_sd_configs": [
                                    {
                                        "role": "endpoints"
                                    }
                                ],
                                "relabel_configs": [
                                    {
                                        "source_labels": [
                                            "__meta_kubernetes_service_annotation_prometheus_io_scrape"
                                        ],
                                        "action": "keep",
                                        "regex": True
                                    },
                                    {
                                        "source_labels": [
                                            "__meta_kubernetes_service_annotation_prometheus_io_scrape_slow"
                                        ],
                                        "action": "drop",
                                        "regex": True
                                    },
                                    {
                                        "source_labels": [
                                            "__meta_kubernetes_service_annotation_prometheus_io_scheme"
                                        ],
                                        "action": "replace",
                                        "target_label": "__scheme__",
                                        "regex": "(https?)"
                                    },
                                    {
                                        "source_labels": [
                                            "__meta_kubernetes_service_annotation_prometheus_io_path"
                                        ],
                                        "action": "replace",
                                        "target_label": "__metrics_path__",
                                        "regex": "(.+)"
                                    },
                                    {
                                        "source_labels": [
                                            "__address__",
                                            "__meta_kubernetes_service_annotation_prometheus_io_port"
                                        ],
                                        "action": "replace",
                                        "target_label": "__address__",
                                        "regex": "(.+?)(?::\\d+)?;(\\d+)",
                                        "replacement": "$1:$2"
                                    },
                                    {
                                        "action": "labelmap",
                                        "regex": "__meta_kubernetes_service_annotation_prometheus_io_param_(.+)",
                                        "replacement": "__param_$1"
                                    },
                                    {
                                        "action": "labelmap",
                                        "regex": "__meta_kubernetes_service_label_(.+)"
                                    },
                                    {
                                        "source_labels": [
                                            "__meta_kubernetes_namespace"
                                        ],
                                        "action": "replace",
                                        "target_label": "namespace"
                                    },
                                    {
                                        "source_labels": [
                                            "__meta_kubernetes_service_name"
                                        ],
                                        "action": "replace",
                                        "target_label": "service"
                                    },
                                    {
                                        "source_labels": [
                                            "__meta_kubernetes_pod_node_name"
                                        ],
                                        "action": "replace",
                                        "target_label": "node"
                                    }
                                ]
                            },
                            {
                                "job_name": "kubernetes-service-endpoints-slow",
                                "honor_labels": True,
                                "scrape_interval": "5m",
                                "scrape_timeout": "30s",
                                "kubernetes_sd_configs": [
                                    {
                                        "role": "endpoints"
                                    }
                                ],
                                "relabel_configs": [
                                    {
                                        "source_labels": [
                                            "__meta_kubernetes_service_annotation_prometheus_io_scrape_slow"
                                        ],
                                        "action": "keep",
                                        "regex": True
                                    },
                                    {
                                        "source_labels": [
                                            "__meta_kubernetes_service_annotation_prometheus_io_scheme"
                                        ],
                                        "action": "replace",
                                        "target_label": "__scheme__",
                                        "regex": "(https?)"
                                    },
                                    {
                                        "source_labels": [
                                            "__meta_kubernetes_service_annotation_prometheus_io_path"
                                        ],
                                        "action": "replace",
                                        "target_label": "__metrics_path__",
                                        "regex": "(.+)"
                                    },
                                    {
                                        "source_labels": [
                                            "__address__",
                                            "__meta_kubernetes_service_annotation_prometheus_io_port"
                                        ],
                                        "action": "replace",
                                        "target_label": "__address__",
                                        "regex": "(.+?)(?::\\d+)?;(\\d+)",
                                        "replacement": "$1:$2"
                                    },
                                    {
                                        "action": "labelmap",
                                        "regex": "__meta_kubernetes_service_annotation_prometheus_io_param_(.+)",
                                        "replacement": "__param_$1"
                                    },
                                    {
                                        "action": "labelmap",
                                        "regex": "__meta_kubernetes_service_label_(.+)"
                                    },
                                    {
                                        "source_labels": [
                                            "__meta_kubernetes_namespace"
                                        ],
                                        "action": "replace",
                                        "target_label": "namespace"
                                    },
                                    {
                                        "source_labels": [
                                            "__meta_kubernetes_service_name"
                                        ],
                                        "action": "replace",
                                        "target_label": "service"
                                    },
                                    {
                                        "source_labels": [
                                            "__meta_kubernetes_pod_node_name"
                                        ],
                                        "action": "replace",
                                        "target_label": "node"
                                    }
                                ]
                            },
                            {
                                "job_name": "prometheus-pushgateway",
                                "honor_labels": True,
                                "kubernetes_sd_configs": [
                                    {
                                        "role": "service"
                                    }
                                ],
                                "relabel_configs": [
                                    {
                                        "source_labels": [
                                            "__meta_kubernetes_service_annotation_prometheus_io_probe"
                                        ],
                                        "action": "keep",
                                        "regex": "pushgateway"
                                    }
                                ]
                            },
                            {
                                "job_name": "kubernetes-services",
                                "honor_labels": True,
                                "metrics_path": "/probe",
                                "params": {
                                    "module": [
                                        "http_2xx"
                                    ]
                                },
                                "kubernetes_sd_configs": [
                                    {
                                        "role": "service"
                                    }
                                ],
                                "relabel_configs": [
                                    {
                                        "source_labels": [
                                            "__meta_kubernetes_service_annotation_prometheus_io_probe"
                                        ],
                                        "action": "keep",
                                        "regex": True
                                    },
                                    {
                                        "source_labels": [
                                            "__address__"
                                        ],
                                        "target_label": "__param_target"
                                    },
                                    {
                                        "target_label": "__address__",
                                        "replacement": "blackbox"
                                    },
                                    {
                                        "source_labels": [
                                            "__param_target"
                                        ],
                                        "target_label": "instance"
                                    },
                                    {
                                        "action": "labelmap",
                                        "regex": "__meta_kubernetes_service_label_(.+)"
                                    },
                                    {
                                        "source_labels": [
                                            "__meta_kubernetes_namespace"
                                        ],
                                        "target_label": "namespace"
                                    },
                                    {
                                        "source_labels": [
                                            "__meta_kubernetes_service_name"
                                        ],
                                        "target_label": "service"
                                    }
                                ]
                            },
                            {
                                "job_name": "kubernetes-pods",
                                "honor_labels": True,
                                "kubernetes_sd_configs": [
                                    {
                                        "role": "pod"
                                    }
                                ],
                                "relabel_configs": [
                                    {
                                        "source_labels": [
                                            "__meta_kubernetes_pod_annotation_prometheus_io_scrape"
                                        ],
                                        "action": "keep",
                                        "regex": True
                                    },
                                    {
                                        "source_labels": [
                                            "__meta_kubernetes_pod_annotation_prometheus_io_scrape_slow"
                                        ],
                                        "action": "drop",
                                        "regex": True
                                    },
                                    {
                                        "source_labels": [
                                            "__meta_kubernetes_pod_annotation_prometheus_io_scheme"
                                        ],
                                        "action": "replace",
                                        "regex": "(https?)",
                                        "target_label": "__scheme__"
                                    },
                                    {
                                        "source_labels": [
                                            "__meta_kubernetes_pod_annotation_prometheus_io_path"
                                        ],
                                        "action": "replace",
                                        "target_label": "__metrics_path__",
                                        "regex": "(.+)"
                                    },
                                    {
                                        "source_labels": [
                                            "__meta_kubernetes_pod_annotation_prometheus_io_port",
                                            "__meta_kubernetes_pod_ip"
                                        ],
                                        "action": "replace",
                                        "regex": "(\\d+);(([A-Fa-f0-9]{1,4}::?){1,7}[A-Fa-f0-9]{1,4})",
                                        "replacement": "[$2]:$1",
                                        "target_label": "__address__"
                                    },
                                    {
                                        "source_labels": [
                                            "__meta_kubernetes_pod_annotation_prometheus_io_port",
                                            "__meta_kubernetes_pod_ip"
                                        ],
                                        "action": "replace",
                                        "regex": "(\\d+);((([0-9]+?)(\\.|$)){4})",
                                        "replacement": "$2:$1",
                                        "target_label": "__address__"
                                    },
                                    {
                                        "action": "labelmap",
                                        "regex": "__meta_kubernetes_pod_annotation_prometheus_io_param_(.+)",
                                        "replacement": "__param_$1"
                                    },
                                    {
                                        "action": "labelmap",
                                        "regex": "__meta_kubernetes_pod_label_(.+)"
                                    },
                                    {
                                        "source_labels": [
                                            "__meta_kubernetes_namespace"
                                        ],
                                        "action": "replace",
                                        "target_label": "namespace"
                                    },
                                    {
                                        "source_labels": [
                                            "__meta_kubernetes_pod_name"
                                        ],
                                        "action": "replace",
                                        "target_label": "pod"
                                    },
                                    {
                                        "source_labels": [
                                            "__meta_kubernetes_pod_phase"
                                        ],
                                        "regex": "Pending|Succeeded|Failed|Completed",
                                        "action": "drop"
                                    },
                                    {
                                        "source_labels": [
                                            "__meta_kubernetes_pod_node_name"
                                        ],
                                        "action": "replace",
                                        "target_label": "node"
                                    }
                                ]
                            },
                            {
                                "job_name": "kubernetes-pods-slow",
                                "honor_labels": True,
                                "scrape_interval": "5m",
                                "scrape_timeout": "30s",
                                "kubernetes_sd_configs": [
                                    {
                                        "role": "pod"
                                    }
                                ],
                                "relabel_configs": [
                                    {
                                        "source_labels": [
                                            "__meta_kubernetes_pod_annotation_prometheus_io_scrape_slow"
                                        ],
                                        "action": "keep",
                                        "regex": True
                                    },
                                    {
                                        "source_labels": [
                                            "__meta_kubernetes_pod_annotation_prometheus_io_scheme"
                                        ],
                                        "action": "replace",
                                        "regex": "(https?)",
                                        "target_label": "__scheme__"
                                    },
                                    {
                                        "source_labels": [
                                            "__meta_kubernetes_pod_annotation_prometheus_io_path"
                                        ],
                                        "action": "replace",
                                        "target_label": "__metrics_path__",
                                        "regex": "(.+)"
                                    },
                                    {
                                        "source_labels": [
                                            "__meta_kubernetes_pod_annotation_prometheus_io_port",
                                            "__meta_kubernetes_pod_ip"
                                        ],
                                        "action": "replace",
                                        "regex": "(\\d+);(([A-Fa-f0-9]{1,4}::?){1,7}[A-Fa-f0-9]{1,4})",
                                        "replacement": "[$2]:$1",
                                        "target_label": "__address__"
                                    },
                                    {
                                        "source_labels": [
                                            "__meta_kubernetes_pod_annotation_prometheus_io_port",
                                            "__meta_kubernetes_pod_ip"
                                        ],
                                        "action": "replace",
                                        "regex": "(\\d+);((([0-9]+?)(\\.|$)){4})",
                                        "replacement": "$2:$1",
                                        "target_label": "__address__"
                                    },
                                    {
                                        "action": "labelmap",
                                        "regex": "__meta_kubernetes_pod_annotation_prometheus_io_param_(.+)",
                                        "replacement": "__param_$1"
                                    },
                                    {
                                        "action": "labelmap",
                                        "regex": "__meta_kubernetes_pod_label_(.+)"
                                    },
                                    {
                                        "source_labels": [
                                            "__meta_kubernetes_namespace"
                                        ],
                                        "action": "replace",
                                        "target_label": "namespace"
                                    },
                                    {
                                        "source_labels": [
                                            "__meta_kubernetes_pod_name"
                                        ],
                                        "action": "replace",
                                        "target_label": "pod"
                                    },
                                    {
                                        "source_labels": [
                                            "__meta_kubernetes_pod_phase"
                                        ],
                                        "regex": "Pending|Succeeded|Failed|Completed",
                                        "action": "drop"
                                    },
                                    {
                                        "source_labels": [
                                            "__meta_kubernetes_pod_node_name"
                                        ],
                                        "action": "replace",
                                        "target_label": "node"
                                    }
                                ]
                            },
                            {
                                "job_name": "karpenter",
                                "kubernetes_sd_configs": [
                                    {
                                        "role": "endpoints",
                                        "namespaces": {
                                            "names": [
                                                "karpenter"
                                            ]
                                        }
                                    }
                                ],
                                "relabel_configs": [
                                    {
                                        "source_labels": [
                                            "__meta_kubernetes_endpoint_port_name"
                                        ],
                                        "regex": "http-metrics",
                                        "action": "keep"
                                    }
                                ]
                            }
                        ]
                    }
               }
           }
    




