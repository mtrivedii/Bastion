variable "region" {
  description = "AWS region."
  type        = string
  default     = "eu-west-1"
}

variable "name" {
  description = "Name prefix for everything created."
  type        = string
  default     = "bastion"
}

variable "kubernetes_version" {
  description = "EKS control plane version."
  type        = string
  default     = "1.31"
}

variable "node_instance_types" {
  description = "Instance types for the worker nodes."
  type        = list(string)
  default     = ["t3.small"]
}

variable "node_count" {
  description = "Number of worker nodes."
  type        = number
  default     = 2
}

variable "api_allowed_cidrs" {
  description = "CIDR ranges allowed to reach the public Kubernetes API. Set this to your own address, for example [\"203.0.113.7/32\"]."
  type        = list(string)
}

variable "monthly_budget_usd" {
  description = "Monthly spend that triggers an email alert."
  type        = number
  default     = 20
}

variable "budget_alert_email" {
  description = "Email address that receives budget alerts."
  type        = string
}
