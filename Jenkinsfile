@Library('libpipelines') _

hose {
    EMAIL = 'clouds-integration@stratio.com'
    BUILDTOOL = 'make'
    DEVTIMEOUT = 30
    BUILDTOOL_IMAGE = 'golang:1.20'
    VERSIONING_TYPE = 'stratioVersion-3-3'
    UPSTREAM_VERSION = '0.17.0'
    DEPLOYONPRS = true
    GRYPE_TEST = true
    MODULE_LIST = [ "paas.cloud-provisioner:cloud-provisioner:tar.gz" ]

    BUILDTOOL_MEMORY_REQUEST = "1024Mi"
    BUILDTOOL_MEMORY_LIMIT = "4096Mi"

    DEV = { config ->
        doPackage(conf: config, parameters: "GOCACHE=/tmp")
        doDeploy(conf: config)
        doCustomStage(conf:config, buildToolOverride: [CUSTOM_COMMAND: 'mkdir -p CTS/resources; tar zxvf bin/cloud-provisioner.tar.gz -C CTS/resources/; chmod -R 0700 CTS/resources/bin/cloud-provisioner'], stageName: "Extract binary")
        doCustomStage(conf:config, buildToolOverride: [CUSTOM_COMMAND: 'cp -r scripts CTS/resources'], stageName: "prepare upgrade script files")
        doDockers(
            conf: config,
            dockerImages: [
                [
                    conf: config,
                    dockerfile: "pkg/cluster/internal/providers/docker/stratio/Dockerfile",
                    image:"cloud-provisioner"
                ],
                [
                    conf: config,
                    dockerfile: "pkg/cluster/internal/providers/docker/stratio/upgrade/Dockerfile",
                    image:"cloud-provisioner-upgrade",
                    skipOnPR: false,
                    buildargs: [
                        "CLUSTERCTL=v1.7.4",
                        "PYTHON_VERSION=3.12",
                        "KUBECTL_VERSION=1.30.1",
                        "HELM_VERSION=3.15.2",
                        "CAPA=v2.5.2",
                        "CAPG=1.6.1-0.3.1",
                        "CAPZ=v1.12.4",
                        "UPGRADE_DIR=CTS/resources/scripts",
                    ]
                ]
            ]
        )
        doGrypeScan(conf: config, artifactsList: [[path: 'CTS/resources/bin/cloud-provisioner', name: 'cloud-provisioner']])
        doAT(conf: config, buildToolOverride: ['BUILDTOOL_IMAGE': 'stratio/cloud-testing-suite:0.1.0-SNAPSHOT', 'BUILDTOOL_PRIVILEGED': true, 'BUILDTOOL_RUNASUSER': "0"],  configFiles: [[fileId: "clouds-credentials.yaml", variable: "credentials"]], runOnPR: true)
    }

    DOC = { config ->
        doStratioDocsChecks(conf: config)
    }
}
