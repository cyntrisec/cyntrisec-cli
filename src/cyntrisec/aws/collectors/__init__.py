"""AWS resource collectors."""

from cyntrisec.aws.collectors.ec2 import Ec2Collector
from cyntrisec.aws.collectors.iam import IamCollector
from cyntrisec.aws.collectors.lambda_ import LambdaCollector
from cyntrisec.aws.collectors.network import NetworkCollector
from cyntrisec.aws.collectors.rds import RdsCollector
from cyntrisec.aws.collectors.s3 import S3Collector

__all__ = [
    "Ec2Collector",
    "IamCollector",
    "S3Collector",
    "LambdaCollector",
    "RdsCollector",
    "NetworkCollector",
]
