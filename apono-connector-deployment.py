import json
import base64


def GenerateConfig(context):
    """Generate YAML resource configuration."""

    region = context.properties['CLUSTER_REGION']
    apono_connector_id = context.properties['APONO_CONNECTOR_ID']
    apono_token = context.properties['APONO_TOKEN']
    github_token = context.properties['GITHUB_TOKEN']

    project = context.env['project']
    cluster_name = 'apono-connector-cluster'

    resources = []
    outputs = []

    resources.append({
        'name': 'apono-connector-iam-sa',
        'type': 'gcp-types/iam-v1:projects.serviceAccounts',
        'properties': {
            'accountId': 'apono-connector-iam-sa',
            'displayName': 'apono-connector-iam-sa'
        },
        'accessControl': {
            'gcpIamPolicy': {
                'bindings': [{
                    'role': 'roles/iam.workloadIdentityUser',
                    'members': [('serviceAccount:%s.svc.id.goog[default/apono-connector-service-account]' % project)]
                }]
            }
        }
    })

    resources.append({
        'name': 'bind-role-to-connector-sa-1',
        'type': 'gcp-types/cloudresourcemanager-v1:virtual.projects.iamMemberBinding',
        'properties': {
            'resource': project,
            'role': 'roles/secretmanager.secretAccessor',
            'member': 'serviceAccount:$(ref.apono-connector-iam-sa.email)'
        }
    })

    resources.append({
        'name': 'bind-role-to-connector-sa-2',
        'type': 'gcp-types/cloudresourcemanager-v1:virtual.projects.iamMemberBinding',
        'properties': {
            'resource': project,
            'role': 'roles/iam.securityAdmin',
            'member': 'serviceAccount:$(ref.apono-connector-iam-sa.email)'
        }
    })

    resources.append({
        'name': cluster_name,
        'type': 'gcp-types/container-v1:projects.locations.clusters',
        'properties': {
            'parent': 'projects/' + project + '/locations/' + region,
            'cluster': {
                'name': cluster_name,
                'location': region,
                'autopilot': {
                    'enabled': True
                },
                'privateClusterConfig': {
                    'enablePrivateNodes': True
                }
            }
        }
    })

    resources.append({
        'name': 'kubernetes-type',
        'type': 'deploymentmanager.v2beta.typeProvider',
        'properties': {
            'options': {
                'validationOptions': {
                    # Kubernetes API accepts ints, in fields they annotate
                    # with string. This validation will show as warning
                    # rather than failure for Deployment Manager.
                    # https://github.com/kubernetes/kubernetes/issues/2971
                    'schemaValidation': 'IGNORE_WITH_WARNINGS'
                },
                # According to kubernetes spec, the path parameter 'name'
                # should be the value inside the metadata field
                # https://github.com/kubernetes/community/blob/master
                # /contributors/devel/api-conventions.md
                # This mapping specifies that
                'inputMappings': [{
                    'fieldName': 'name',
                    'location': 'PATH',
                    'methodMatch': '^(GET|DELETE|PUT|POST|PATCH)$',
                    'value': '$.ifNull('
                             '$.resource.properties.metadata.name, '
                             '$.resource.name)'
                }, {
                    'fieldName': 'metadata.name',
                    'location': 'BODY',
                    'methodMatch': '^(PUT|POST)$',
                    'value': '$.ifNull('
                             '$.resource.properties.metadata.name, '
                             '$.resource.name)'
                }, {
                    'fieldName': 'Authorization',
                    'location': 'HEADER',
                    'value': '$.concat("Bearer ",'
                             '$.googleOauth2AccessToken())'
                }, {
                    'fieldName': 'metadata.resourceVersion',
                    'location': 'BODY',
                    'methodMatch': '^(PUT|PATCH)$',
                    'value': '$.resource.self.metadata.resourceVersion'
                }, {
                    'fieldName': 'id',
                    'location': 'PATH',
                    'methodMatch': '^(GET|DELETE|PUT|POST|PATCH)$',
                    'value': '$.resource.properties.id'
                }, {
                    'fieldName': 'namespace',
                    'location': 'PATH',
                    'methodMatch': '^(GET|DELETE|PUT|POST|PATCH)$',
                    'value': '$.resource.properties.namespace'
                }]
            },
            'descriptorUrl':
                ''.join([
                    'https://$(ref.', cluster_name, '.endpoint)/openapi/v2'
                ])
        }
    })

    resources.append({
        'name': 'apono-connector',
        'type': project + '/kubernetes-type' + ':/apis/apps/v1/namespaces/{namespace}/deployments/{name}',
        'metadata': {
            'dependsOn': ['kubernetes-type']
        },
        'properties': {
            'apiVersion': 'apps/v1',
            'kind': 'Deployment',
            'namespace': 'default',
            'metadata': {
                'name': 'apono-connector'
            },
            'spec': {
                'replicas': 1,
                'selector': {
                    'matchLabels': {
                        'app': 'apono-connector'
                    }
                },
                'template': {
                    'metadata': {
                        'deletePolicy': 'ABANDON',
                        'labels': {
                            'app': 'apono-connector'
                        }
                    },
                    'spec': {
                        'serviceAccountName': 'apono-connector-service-account',
                        'imagePullSecrets': [{
                            'name': 'apono-docker-registry'
                        }],
                        'containers': [{
                            'name': 'apono-connector',
                            'image': 'ghcr.io/apono-io/apono-connector:18065ff38a981842fb208c29e6990f28279b1cf5',
                            'env': [
                                {
                                    'name': 'APONO_CONNECTOR_ID',
                                    'value': apono_connector_id
                                },
                                {
                                    'name': 'APONO_TOKEN',
                                    'value': apono_token
                                },
                                {
                                    'name': 'APONO_URL',
                                    'value': 'api.apono.io'
                                },
                                {
                                    'name': 'TEMPLATES_PATH',
                                    'value': '/app/apono-agent-templates'
                                }
                            ]
                        }]
                    }
                }
            }
        }
    })

    resources.append({
        'name': 'apono-docker-registry',
        'type': project + '/kubernetes-type' + ':/api/v1/namespaces/{namespace}/secrets/{name}',
        'metadata': {
            'dependsOn': ['kubernetes-type']
        },
        'properties': {
            'apiVersion': 'v1',
            'kind': 'Secret',
            'namespace': 'default',
            'metadata': {
                'name': 'apono-docker-registry'
            },
            'type': 'kubernetes.io/dockerconfigjson',
            'data': {
                '.dockerconfigjson': base64.b64encode(
                    json.dumps(
                        {'auths': {'ghcr.io': {'username': 'USERNAME', 'password': github_token}}})
                    .encode('ascii')
                )
            }
        }
    })

    resources.append({
        'name': 'apono-connector-k8s-sa',
        'type': project + '/kubernetes-type' + ':/api/v1/namespaces/{namespace}/serviceaccounts/{name}',
        'metadata': {
            'dependsOn': ['kubernetes-type']
        },
        'properties': {
            'namespace': 'default',
            'metadata': {
                'name': 'apono-connector-service-account',
                'annotations': {
                    'iam.gke.io/gcp-service-account': '$(ref.apono-connector-iam-sa.email)'
                }
            }
        }
    })


    outputs.append({
        'name': 'endpoint',
        'value': '$(ref.' + cluster_name + '.endpoint)'
    })

    return {'resources': resources, 'outputs': outputs}