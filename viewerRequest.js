"use strict";
const jwt = require("jsonwebtoken");
const aws = require("aws-sdk");
const ssm = new aws.SSM({ region: "us-east-1" });
let secret;
const getSecret = async () => {
  const params = {
    Name: "/lambdaedge/jwt-secret",
    WithDecryption: true,
  };
  const secret = await ssm.getParameter(params).promise();
  return secret && secret.Parameter && secret.Parameter.Value;
};

exports.handler = async (event, context, callback) => {
  const request = event.Records[0].cf.request;
  const querystring = request.querystring;
  if (querystring) {
    const tokenMatch = querystring.match("token=([^&]+)");
    const token = tokenMatch[1];
    if (token) {
      try {
        if (!secret) {
          secret = await getSecret();
        }

        const { key } = jwt.verify(token, secret);
        request.uri = `/${key}`;
        callback(null, request);
      } catch (error) {
        console.error("Invalid JWT token");
        const response = {
          status: "401",
          statusDescription: "Unauthorized JWT",
          headers: {
            location: [
              {
                key: "Location",
                value: "www.mianio.com/401",
              },
            ],
          },
        };
        callback(null, response);
      }
    }
  }

  const unauthorizedResponse = {
    status: "403",
    statusDescription: "Forbidden",
    headers: {
      location: [
        {
          key: "Location",
          value: "www.mianio.com/403",
        },
      ],
    },
  };

  callback(null, unauthorizedResponse);
};
