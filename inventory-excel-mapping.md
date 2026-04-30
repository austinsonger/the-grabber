




Inventory Excel Mapping

Maps the app's inventory fields to the FedRAMP Excel template columns and shows which AWS fields or derived values populate each one.

| Excel col | Excel/App field | AWS source used in code |
| --- | --- | --- |
| A | UNIQUE ASSET IDENTIFIER | **KMS:** `DescribeKey.KeyMetadata.Arn` · **S3:** `ListBuckets.Bucket.Name` · **Lambda:** `ListFunctions.FunctionArn` · **EC2:** `DescribeInstances.InstanceId` · **ALB:** `DescribeLoadBalancers.LoadBalancerArn` · **RDS:** `DescribeDBInstances.DBInstanceArn` · **ElastiCache:** `ReplicationGroup.Arn` else `ReplicationGroupId` · **Container:** `DescribeRepositories.RepositoryUri` |
| B | IPv4 or IPv6 Address | **EC2 only:** `DescribeInstances.PrivateIpAddress` |
| C | Virtual | Constant `"Yes"` for all collected AWS assets |
| D | Public | **S3:** `GetBucketPolicyStatus.PolicyStatus.IsPublic` · **EC2:** derived from `PublicIpAddress != ""` · **ALB:** `Scheme == internet-facing` · **RDS:** `PubliclyAccessible` · others hard-coded `"No"` |
| E | DNS Name or URL | **S3:** derived `https://{bucket}.s3.{region}.amazonaws.com` · **EC2:** `PublicDnsName` else `PrivateDnsName` · **ALB:** `DNSName` · **RDS:** `Endpoint.Address` · **ElastiCache:** `ConfigurationEndpoint.Address` else primary endpoint |
| G | MAC Address | **EC2 only:** first `NetworkInterfaces[].MacAddress` |
| K | Location | **KMS/Lambda:** selected AWS region · **S3:** `GetBucketLocation.LocationConstraint` normalized · **EC2:** `region / Placement.AvailabilityZone` · **ALB:** `region / AvailabilityZones[].ZoneName` · **RDS:** derived from `DBSubnetGroupName` + `VpcId` · **ElastiCache:** derived from cache subnet group + `VpcId` · **Container:** `region / ECR Repo: {repository_name}` |
| L | Asset Type | Hard-coded label: `KMS Key`, `S3 Bucket`, `Lambda Function`, `EC2 Instance`, `Application Load Balancer`, `RDS DB Instance`, `ElastiCache Cluster`, `Container Image` |
| M | Hardware Make/Model | **EC2:** `AWS EC2 {InstanceType}` · **ALB:** constant `AWS ALB` · **RDS:** `AWS RDS {DBInstanceClass}` · **ElastiCache:** `AWS ElastiCache {CacheNodeType}` |
| O | Software/ Database Vendor | **KMS/S3/Lambda/EC2/ALB:** constant `Amazon Web Services` · **RDS:** derived from `Engine` (`PostgreSQL`, `MySQL`, `Oracle`, `Microsoft`, or AWS) · **ElastiCache:** derived from `Engine` (`Redis`, `Memcached`, or AWS) · **Container:** `RepositoryName` |
| P | Software/ Database Name & Version | **KMS:** `AWS Key Management Service (KMS)` · **S3:** `Amazon S3` · **Lambda:** `AWS Lambda | Runtime: {Runtime}` · **EC2:** `Amazon EC2` · **ALB:** `AWS ELBv2 (application)` · **RDS:** `{Engine} {EngineVersion}` · **ElastiCache:** `{Engine} {EngineVersion}` · **Container:** `RepositoryName` or `RepositoryName | Tags: {ImageTags}` |
| S | Comments | Derived summary fields. Examples: **KMS:** key metadata/rotation · **S3:** public access, encryption, versioning, logging · **Lambda:** role, KMS key, VPC, timeout, memory, DLQ · **ALB:** VPC, SGs, IP type, listeners · **Container:** repo/image metadata, tags, ECS/EKS refs |
| U | VLAN/ Network ID | **Lambda:** derived `VPC: {VpcId}, Subnets: {SubnetIds}` · **EC2:** derived `VPC: {VpcId}, Subnet: {SubnetId}` · **ALB/RDS/ElastiCache:** derived VPC + subnet IDs |
| X | Function | **KMS:** `DescribeKey.KeyMetadata.Description` · **S3:** first matching bucket tag value from `Purpose/App/Role/Function` · **Lambda:** `Description` else `FunctionName` |

