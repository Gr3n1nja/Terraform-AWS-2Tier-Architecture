# Terraform-AWS-2Tier-Architecture
Basic Terraform module to deploy a simple two-tier architecture on AWS.

### **AWS Terraform Deployment and Testing Steps**

#### **Prerequisites**

1. Install [Terraform](https://www.terraform.io/downloads.html).
2. Set up AWS CLI and configure with appropriate access credentials (`aws configure`).

Before executing:
1. Replace the placeholders `YOUR_AWS_ACCESS_KEY` and `YOUR_AWS_SECRET_KEY` with your AWS credentials.
2. Replace `S3_BUCKET_NAME`, `AMI-ID`, `DB_USER` & `DB_PASS` with your required AWS config.

#### **Deployment Steps**

1. **Initialize Terraform Directory:**
    ```bash
    terraform init
    ```

2. **Validate the script:**
    ```bash
    terraform validate
    ```

3. **Plan the Deployment:** Check the resources Terraform will create or modify.
    ```bash
    terraform plan
    ```

4. **Apply the Changes:** Deploy the infrastructure.
    ```bash
    terraform apply
    ```

    Confirm by typing `yes` when prompted.

5. **Check AWS Console:** Log in to the AWS Console and navigate to the VPC Dashboard to verify the new VPC, subnets, and other resources.

#### **Testing the Architecture**

1. **Accessing the Application:**
    - Navigate to the ALB's DNS name in a web browser. It should send the request to one of the application instances in the private subnets.

2. **Testing Bastion Host:**
    - SSH into the Bastion host using its public IP:
      ```bash
      ssh -i path_to_key.pem ec2-user@bastion_ip
      ```
    - From the Bastion, SSH into one of the instances in the private subnets.

3. **Testing Database Connectivity:**
    - From one of the application instances in private subnet, try connecting to the RDS instance in the corresponding database subnet.

4. **Monitoring and Logs:**
    - Check CloudTrail in the AWS Console for logs related to AWS API calls.
    - Check CloudWatch for stats on EC2 instances and other resources.

#### **Clean Up**

Once testing is completed and you want to remove all the resources:

```bash
terraform destroy
```

Confirm by typing `yes` when prompted.
