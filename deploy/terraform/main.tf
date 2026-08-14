terraform {
  required_version = ">= 1.6"

  required_providers {
    helm = {
      source  = "hashicorp/helm"
      version = "~> 2.0"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.0"
    }
  }
}

variable "namespace" {
  type    = string
  default = "ddf"
}

resource "kubernetes_namespace_v1" "ddf" {
  metadata {
    name = var.namespace
  }
}

resource "helm_release" "ddf" {
  name      = "ddf"
  namespace = kubernetes_namespace_v1.ddf.metadata[0].name
  chart     = "../helm/ddf"

  atomic          = true
  cleanup_on_fail = true
  wait            = true
}
