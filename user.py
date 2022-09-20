from urllib import response
import boto3
import json
from custom_encoder import CustomEncoder
import logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

dynamodbTableName = 'test-3'
dynamodb = boto3.resource('dynamodb')
table = dynamodb.Table(dynamodbTableName)

getMethod = 'GET'
postMethod = 'POST'
patchMethod = 'PATCH'
deleteMethod = 'DELETE'
healthPath = '/health'
userPath = '/user'
adminsPath = '/admins'

def lambda_handler(event, context):
    logger.info(event)
    httpMethod = event['httpMethod']
    path = event['path']
    if httpMethod == getMethod and path == healthPath:
        response = buildResponse(200)
    elif httpMethod == getMethod and path == userPath:
        response = getuser(event['queryStringParameters']['user_name'])
    elif httpMethod == getMethod and path == adminsPath:
        response = getadmins()
    elif httpMethod == postMethod and path == userPath:
        response = saveuser(json.loads(event['body']))
    elif httpMethod == patchMethod and path == userPath:
        requestBody = json.loads(event['body'])
        response = modifyuser(requestBody['user_name'], requestBody['updateKey'], requestBody['updateValue'])
    elif httpMethod == deleteMethod and path == userPath:
        requestBody = json.loads(event['body'])
        response = deleteuser(requestBody['user_name'])
    else:
        response = buildResponse(404, 'Not Found')

    return response
def getuser(user_name):
    try:
        response = table.get_item(
            Key={
                'user_name': user_name
            }
        )
        if 'Item' in response:
            return buildResponse(200, response['Item'])
        else:
            return buildResponse(404, {'Message': 'user_name: %s not found' % user_name})
    except:
        logger.exception('Do your custom error handling here. I am just gonna log it out here!!')

def getadmins():
    try:
        response = table.scan()
        result = response['Items']

        while 'LastEvaluatedKey' in response:
            response = table.scan(ExclusiveStartKey=response['LastEvaluatedKey'])
            result.extend(response['Items'])
        
        body = {
            'admins': result
        }
        return buildResponse(200, body)
    except:
        logger.exception('Do your custom error handling here. I am just gonna log it out here!!')

def saveuser(requestBody):
    try:
        table.put_item(Item=requestBody)
        body = {
            'Operation': 'SAVE',
            'Message': 'SUCCESS',
            'Item': requestBody
        }
        return buildResponse(200, body)
    except:
        logger.exception('Do your custom error handling here. I am just gonna log it out here!!')

def modifyuser(user_name, updateKey, updateValue):
    try:
        response = table.update_item(
            Key={
                'user_name': user_name
            },
            UpdateExpression='set %s = :value' %updateKey,
            ExpressionAttributeValues={
                ':value': updateValue
            },
            ReturnValues='UPDATED_NEW'
        )
        body = {
            'Operation': 'UPDATE',
            'Message': 'SUCCESS',
            'UpdateAttributes': response
        }
        return buildResponse(200, body)
    except:
        logger.exception('Do your custom error handling here. I am just gonna log it out here!!')

def deleteuser(user_name):
    try:
        response = table.delete_item(
            Key={
                'user_name': user_name
            },
            ReturnValues='ALL_OLD'
        )
        body = {
            'Operation': 'DELETE',
            'Message': 'SUCCESS',
            'deleteItem': response
        }
        return buildResponse(200, body)
    except:
        logger.exception('Do your custom error handling here. I am just gonna log it out here!!')

def buildResponse(statusCode, body=None):
    response = {
        'statusCode': statusCode,
        'headers': {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*'
        }
    }
    if body is not None:
        response['body'] = json.dumps(body, cls=CustomEncoder)
    return response
