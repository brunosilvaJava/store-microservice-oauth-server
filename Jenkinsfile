pipeline {

    environment {
        registry = "brunosilva1988/auth"
        registryCredential = 'dockerhub_id'
        dockerImage = ''
    }

    agent any // defini qual agente irá executar o pipeline. any -> primeiro ambiente disponível (Jenkins Master - Própria máquina)

    stages {
        stage('Clean') {
            steps {
                sh "./mvnw clean"
            }
        }
        stage("Build") {
            steps {
                sh "./mvnw package"
            }
        }
        stage('Test') {
            steps {
                sh "./mvnw test"
            }
        }
        stage('JaCoCo') {
            steps {
                echo 'Code Coverage'
                jacoco()
            }
        }
        stage('Build image') {
            steps {
                script {
                    dockerImage = docker.build registry + ":$BUILD_NUMBER"
                }
            }
        }
        stage('Push image') {
            steps {
                script {
                    docker.withRegistry('', registryCredential) {
                        dockerImage.push()
                    }
                }
            }
        }
        stage('Deploy') {
            steps {
                sh "docker stack deploy --compose-file docker-compose.yml store"
            }
        }
    }
}