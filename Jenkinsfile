pipeline {
    agent any
    environment {
        NEXUS_VERSION = "nexus3"
        NEXUS_PROTOCOL = "http"
        NEXUS_URL = "127.0.0.1:8081"
        NEXUS_REPOSITORY = "system-biblioteczny-maven-nexus-repo"
        NEXUS_CREDENTIAL_ID = "nexus-user-credentials"
        DOCKER_IMAGE = "gateway-api"
        DOCKER_TAG = "${env.BUILD_NUMBER}"
    }
    stages {
        stage('Build') {
            steps {
                sh 'mvn -B -DskipTests clean package'
            }
        }
        stage('Save Artifacts to Nexus'){
            when {
                expression {
                    env.GIT_BRANCH == 'origin/main'
                }
            }
            steps {
                script {
                    pom = readMavenPom file: "pom.xml";
                    filesByGlob = findFiles(glob: "target/*.${pom.packaging}");
                    echo "${filesByGlob[0].name} ${filesByGlob[0].path} ${filesByGlob[0].directory} ${filesByGlob[0].length} ${filesByGlob[0].lastModified}"
                    artifactPath = filesByGlob[0].path;
                    artifactExists = fileExists artifactPath;
                    if(artifactExists) {
                        echo "*** File: ${artifactPath}, group: ${pom.groupId}, packaging: ${pom.packaging}, version ${pom.version}";
                        nexusArtifactUploader(
                            nexusVersion: NEXUS_VERSION,
                            protocol: NEXUS_PROTOCOL,
                            nexusUrl: NEXUS_URL,
                            groupId: pom.groupId,
                            version: pom.version,
                            repository: NEXUS_REPOSITORY,
                            credentialsId: NEXUS_CREDENTIAL_ID,
                            artifacts: [
                                [artifactId: pom.artifactId,
                                classifier: '',
                                file: artifactPath,
                                type: pom.packaging],
                                [artifactId: pom.artifactId,
                                classifier: '',
                                file: "pom.xml",
                                type: "pom"]
                            ]
                        );
                    } else {
                        error "*** File: ${artifactPath}, could not be found";
                    }
                }
            }
        }
        stage('Docker Build and Deploy') {
//             when {
//                 expression {
//                     env.GIT_BRANCH == 'origin/main'
//                 }
//             }
            steps {
                sh "docker build -t ${DOCKER_IMAGE}:${DOCKER_TAG} ."

                sh "docker rm -f ${DOCKER_IMAGE} || true"

                sh "docker run -d --name ${DOCKER_IMAGE} --network auth-api_shared-network -p 8180:8180 ${DOCKER_IMAGE}:${DOCKER_TAG}"
            }
        }
    }
}
