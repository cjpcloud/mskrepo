
aws cloudformation create-stack --stack-name vpc --template-body file://vpc.yaml
sleep 600
aws cloudformation create-stack --stack-name mskcluster --template-body file://mskcluster.yaml
sleep 2200
aws kafka list-clusters-v2|grep ClusterName
echo "Enter Cluster Name starting from / "Example: /Properties""
read clustername
cluster_arn=`aws kafka list-clusters-v2|grep ClusterArn|awk '{print$2}'|grep $clustername|sed -e 's/"//gi'|sed -e 's/,//gi'`
echo "mskcluster arn:" $cluster_arn
version=`aws kafka describe-cluster --cluster-arn $cluster_arn|grep CurrentVersion|awk '{print$2}'|sed -e 's/"//gi'|sed -e 's/,//gi'`
echo "mskcluster version:" $version 

aws kafka update-connectivity --cluster-arn $cluster_arn --current-version $version --connectivity-info '{"PublicAccess": {"Type": "SERVICE_PROVIDED_EIPS"}}'

aws kafka describe-cluster --cluster-arn $cluster_arn|grep State


