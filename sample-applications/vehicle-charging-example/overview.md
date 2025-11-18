

    Charging stations (electric vehicle supply equipment, or EVSE) are connected to Amazon Elastic Container Service (Amazon ECS)on AWS Fargate behind Network Load Balancer. AWS Lambda routes outbound open charge point protocol (OCPP) messages to EVSEs and Amazon DynamoDB keeps active connections.

    Amazon CloudFront serves static EVSE management web application from an Amazon Simple Storage Service (Amazon S3) bucket. Amazon API Gateway exposes the backend REST API for the web application. Amazon Cognito stores the Charging Point Operator’s user identities.

    DynamoDB stores the registry of EVSE with credentials in encrypted form. AWS Certificate Manager (ACM) manages EVSE certificates for authentication.

    Management microservice delivers EVSE metrics to and from Amazon CloudWatch. Amazon S3 is used to store EVSE logs, cold metrics, and firmware files.

    The configuration of charging sites, balancing algorithms, and power grid capacity stored in DynamoDB.

    Amazon Quantum Ledger Database (Amazon QLDB) stores immutable and cryptographically verifiable log of charging transactions.

    Application Load Balancer exposes the internal APIs of the microservices, routes requests, and balances between multiple tasks on Amazon ECS.
