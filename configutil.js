const aws = require('aws-sdk');
const mysql = require('mysql');
const MongoClient = require('mongodb').MongoClient;

const loadConfigs = (configs) => {
    return {
        s3: new aws.S3({
            endpoint: new aws.Endpoint('sgp1.digitaloceanspaces.com'),
            accessKeyId: configs.s3.accessKey,
            secretAccessKey: configs.s3.secret
            }),
        pool: mysql.createPool(configs.mysql)
        ,
        client: new MongoClient(configs.mongodb.url, { useUnifiedTopology: true })
    }
}

const testConns = (configs) => {
    const p = [];
    p.push(new Promise((resolve, reject) => {
        configs.pool.getConnection((err, conn) =>{
            if (err)
                return reject(err)
            conn.ping((err) => {
                conn.release();
                if (err)
                    return reject(err);
                console.log('resolved mysql');
                resolve();
            })
        })
    }));
    
    p.push(new Promise((resolve, reject) => {
        configs.client.connect((error,_) => {
			if (error)
                return reject(error);
            console.log('resolved mongodb');
			resolve();
        })
    }));

    p.push(new Promise((resolve, reject) => {
			const params = {
				Bucket: 'free-images',
				Key: 'btc.jpg'
			}
			configs.s3.getObject(params,
				(err, result) => {
					if (err)
						return reject(err);
					console.info('resolved s3');
					resolve();
				}
			)
		}
    ))
    return Promise.all(p);
}

module.exports = { loadConfigs, testConns };