while getopts p:y: flag
do
    case "${flag}" in
        p) proto=${OPTARG};;
        y) yaml=${OPTARG};;
    esac
done

protoc --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative $proto
protoc --grpc-gateway_out=. --grpc-gateway_opt=logtostderr=true --grpc-gateway_opt=paths=source_relative --grpc-gateway_opt=grpc_api_configuration=$yaml $proto
protoc --openapiv2_out=. --openapiv2_opt=logtostderr=true --openapiv2_opt=grpc_api_configuration=$yaml --openapiv2_opt=json_names_for_fields=false $proto