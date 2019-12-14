const express = require('express');
const app = express();
const http = require("http").Server(app);
const io = require("socket.io")(http);

const morgan = require('morgan');
const cors = require('cors');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const db = require('./dbutil');
const { loadConfigs, testConns } = require('./configutil');
const jwt = require('jsonwebtoken');

const PORT = parseInt(process.argv[2] || process.env.APP_PORT) || 3000;

//Set up configs for MySQL, Mongo and AWS S3
let configs = {};

if (fs.existsSync(__dirname + '/config.js')) {
	configs = require('./config');
	configs.mysql.ssl = {
		ca: fs.readFileSync(configs.mysql.cacert)
	};

} else {
	configs.mysql = {
		host: process.env.DB_HOST,
		port: process.env.DB_PORT,
		user: process.env.DB_USER,
		password: process.env.DB_PASSWORD,
		database: 'projectmanagement',
		connectionLimit: 4,
		ssl: {
			ca: process.env.DB_CA
		}
	};
	configs.s3 = {
		accessKey: process.env.AWS_ACCESS_KEY_ID,
		secretKey: process.env.AWS_SECRET_ACCESS_KEY
	}
	configs.mongodb = {
		url: process.env.MONGO_CONN_STRING
	}
}

const loadedConfigs = loadConfigs(configs);
const s3 = loadedConfigs.s3;
const pool = loadedConfigs.pool;
const client = loadedConfigs.client;

//SQL Queries
const GET_ALL_TEAMS = 'select * from team';
const getAllTeams = db.mkQueryFromPool(db.mkQuery(GET_ALL_TEAMS), pool);

//users
const CREATE_USER = 'insert into user (username, password, email, team_id, profile_pic_url, grants) values (?,sha2(?,256),?,?,?,?)';
const createUser = db.mkQuery(CREATE_USER);

const FIND_USER = 'select count(*) as user_count from user where username = ? and password = sha2(?, 256)';
const GET_USER_DETAILS = 'select * from user where username = ?'
const findUser = db.mkQueryFromPool(db.mkQuery(FIND_USER), pool);
const getUserDetails = db.mkQueryFromPool(db.mkQuery(GET_USER_DETAILS), pool);

const GET_USER_PROFILE = `select username, email, team_name, profile_pic_url from user join
						   team where user.team_id = team.team_id and username = ?`
const getUserProfile = db.mkQueryFromPool(db.mkQuery(GET_USER_PROFILE), pool);

const GET_PROFILE_PICS_FOR_TEAM = `select username, profile_pic_url from user u join team t 
												where u.team_id = t.team_id and t.team_id = ?`;
const getProfilePicsForTeam = db.mkQueryFromPool(db.mkQuery(GET_PROFILE_PICS_FOR_TEAM), pool);

const UPDATE_USER_PROFILE = 'update user set password = sha2(?, 256), email = ?, profile_pic_url = ? where username = ?';
const updateUserProfile = db.mkQuery(UPDATE_USER_PROFILE);

//get tasks
const GET_ALL_TASKS_BY_USER_TEAM = `select t.task_id, title, status, assigned_to, due_date, item_id, list_item, completed, 
									tb.board_id, board_name, team_id from 
									task t left join task_checklist tc on t.task_id = tc.task_id 
									right join task_board tb on t.board_id = tb.board_id
									where team_id in (select u.team_id from user u join team t on u.team_id = t.team_id
									where username = ?);`
const getAllTasksByUserTeam = db.mkQueryFromPool(db.mkQuery(GET_ALL_TASKS_BY_USER_TEAM), pool);

//add task 
const ADD_TASK = 'insert into task (title, description, status, board_id, created_by) values (?,?,?,?,?)';
const GET_ADDED_TASK_ID = 'select last_insert_id() as task_id from task';
const ADD_CHECKLIST_FOR_TASK = 'insert into task_checklist (task_id, list_item, completed) values ?';

const addTask = db.mkQuery(ADD_TASK);
const getAddedTaskId = db.mkQuery(GET_ADDED_TASK_ID);
const addChecklistForTask = db.mkQuery(ADD_CHECKLIST_FOR_TASK);

//update task
const UPDATE_TASK_DETAILS = 'update task set title = ?, description = ?, assigned_to = ?, due_date = ? where task_id = ?';
const updateTaskDetails = db.mkQuery(UPDATE_TASK_DETAILS);

const DELETE_CHECKLIST = 'delete from task_checklist where task_id = ?';
const deleteChecklist = db.mkQuery(DELETE_CHECKLIST);

//update task status
const UPDATE_TASK_STATUS = 'update task set status = ? where task_id = ?';
const updateTaskStatus = db.mkQueryFromPool(db.mkQuery(UPDATE_TASK_STATUS), pool);

//delete task
const DELETE_TASK = 'delete from task where task_id = ?';
const deleteTask = db.mkQuery(DELETE_TASK);

//get user's team for creating taskboard
const GET_USER_TEAM = 'select team_id from user where username = ?';
const getUserTeam = db.mkQuery(GET_USER_TEAM);

const CREATE_TASK_BOARD = 'insert into task_board (board_name, team_id, created_by) values (?,?,?)';
const createTaskBoard = db.mkQuery(CREATE_TASK_BOARD);

//delete taskboard: delete checklists methods lie within the api end point 
const GET_TASKS_CHECKLIST_ITEMS_FOR_BOARD = `select distinct(t.task_id) from task t right join 
											 task_checklist tc on t.task_id = tc.task_id where board_id = ?`;
const DELETE_TASKS_BY_BOARD = 'delete from task where board_id = ?';
const DELETE_TASK_BOARD = 'delete from task_board where board_id = ?'

const getTasksChecklistItemsForBoard = db.mkQuery(GET_TASKS_CHECKLIST_ITEMS_FOR_BOARD);
const deleteTasksByBoard = db.mkQuery(DELETE_TASKS_BY_BOARD);
const deleteTaskBoard = db.mkQuery(DELETE_TASK_BOARD);

//update taskboard name 
const UPDATE_TASKBOARD_NAME = 'update task_board set board_name = ? where board_id = ?';
const updateTaskboardName = db.mkQueryFromPool(db.mkQuery(UPDATE_TASKBOARD_NAME), pool);

const authenticateUser = (param) => {
	return (
		findUser(param)
			.then(result => (result.length && result[0].user_count > 0))
	)
};

// Load passport and LocalStrategy
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;

passport.use(
	new LocalStrategy(
		{
			usernameField: 'username',
			passwordField: 'password',
		},
		(username, password, done) => {
			authenticateUser([username, password])
				.then(result => {
					if (result)
						return (done(null, username))
					done(null, false);
				})
		}
	)
);

const multipart = multer({ dest: path.join(__dirname, '/tmp') });
app.use(morgan('tiny'));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(__dirname + '/public'));
app.use(passport.initialize())

const grants = [
	{ role: 'user', resource: 'api/taskboards', action: 'read:any' },
	{ role: 'user', resource: 'api/task', action: 'update:any' },
]

app.get('/status/:code',
	(req, res) => {
		// need to do a little more checking
		res.status(parseInt(req.params.code)).json({ message: 'incorrect login' })
	}
)

app.post('/api/authenticate',
	passport.authenticate('local', {
		failureRedirect: '/status/401',
		session: false
	}),
	(req, res) => {
		// issue the JWT
		getUserDetails([req.user])
			.then(result => {
				const d = new Date()
				const rec = result[0];
				const token = jwt.sign({
					sub: rec.username,
					iss: 'proj-management-app',
					iat: d.getTime() / 1000,
					// 15 mins
					exp: (d.getTime() / 1000) + (60 * 10),
					data: {
						email: rec.email,
						teamId: rec.team_id
					}
				}, 'SECRET')

				res.status(200).json({
					username: rec.username,
					team_id: rec.team_id,
					profile_pic_url: rec.profile_pic_url,
					token_type: 'Bearer',
					access_token: token
				})
			})
	}
)

io.on('connection', socket => {
	socket.on('joinRoom', (usernameAndTeamId) => {
		const username = usernameAndTeamId.username;
		const teamId = usernameAndTeamId.teamId;

		//console.info('Room details before join', io.sockets.adapter.rooms[teamId]);
		socket.join(teamId, (err) => {
			//console.log(`${username} joined room ${teamId}`);
			//console.info('Room details after join', io.sockets.adapter.rooms[teamId]);
			socket.to(teamId).emit('joinRoom', `${username} joined room ${teamId}`);
		});
	});

	socket.on('getTaskBoards', (usernameAndTeamId) => {
		const username = usernameAndTeamId.username;
		//const teamId = usernameAndTeamId.teamId;

		const emptyBoards = [];

		getAllTasksByUserTeam([username])
			.then(result => {
				const processedTasks = [];
				let task;

				result.forEach(r => {
					//first check for boards with no tasks
					if (!r.task_id)
						emptyBoards.push({ board_id: r.board_id, board_name: r.board_name });
					if (!!r.task_id) {
						task = processedTasks.find(v => { return v.task_id === r.task_id });
						//if there are checklist items in task
						if (!task && r.item_id !== null) {
							processedTasks.push({
								task_id: r.task_id,
								title: r.title,
								description: r.description || '',
								status: r.status,
								assigned_to: r.assigned_to,
								due_date: r.due_date,
								checklist: [{
									item_id: r.item_id,
									list_item: r.list_item,
									completed: r.completed
								}],
								board_id: r.board_id,
								board_name: r.board_name,
								team_id: r.team_id
							})
						}
						//if no checklist items in task
						else if (!task && r.item_id === null) {
							processedTasks.push({
								task_id: r.task_id,
								title: r.title,
								description: r.description || '',
								status: r.status,
								assigned_to: r.assigned_to,
								due_date: r.due_date,
								checklist: [],
								board_id: r.board_id,
								board_name: r.board_name,
								team_id: r.team_id
							})
						}
						else {
							task.checklist.push({
								item_id: r.item_id,
								list_item: r.list_item,
								completed: r.completed
							})
						}
					}
				})

				const boards = [];
				let board;
				processedTasks.forEach(r => {
					board = boards.find(v => { return v.board_id === r.board_id });

					if (!board) {
						boards.push({
							board_id: r.board_id,
							board_name: r.board_name,
							tasks: [r]
						})
					}
					else {
						board.tasks.push(r);
					}
				})

				//to push in empty task array for empty boards
				emptyBoards.forEach(v => {
					boards.push({
						board_id: v.board_id,
						board_name: v.board_name,
						tasks: []
					})
				})
				socket.emit('boards', boards)
			})
			.catch(error => {
				socket.emit('error', { error: JSON.stringify(error) });
			})
	});

	socket.on('updateTaskBoardName', (boardIdAndNameAndUser) => {
		const username = boardIdAndNameAndUser.username;
		const teamId = boardIdAndNameAndUser.teamId;
		const board_name = boardIdAndNameAndUser.board_name;
		const board_id = boardIdAndNameAndUser.board_id;

		//console.info('Updating task board name by', username);
		updateTaskboardName([board_name, board_id])
			.then(result => {
				socket.emit('newBoardName', { board_name, board_id });
				socket.to(teamId).emit('newBoardName', { board_name, board_id });
			})
			.catch(error => {
				socket.emit('error', { error: JSON.stringify(error) });
			})
	});

	socket.on('createTaskBoard', (usernameAndTeamId) => {
		const username = usernameAndTeamId.username;
		const teamId = usernameAndTeamId.teamId;
		//console.info('Creating new task board by', username);

		pool.getConnection((err, conn) => {
			if (err) {
				socket.emit('error', { error: JSON.stringify(err) });
			}

			db.startTransaction(conn)
				.then(status => {
					return getUserTeam({ connection: status.connection, params: [username] });
				})
				.then(status => {
					const team_id = status.result[0].team_id;
					const params = ['default', team_id, username];
					return createTaskBoard({ connection: status.connection, params });
				})
				.then(db.passthru, db.logError)
				.then(db.commit, db.rollback)
				.then(status => {
					socket.emit('success', 'You created task board');
					socket.to(teamId).emit('success', `${username} from team ${teamId} created task board`);
				}, status => {
					socket.emit('error', 'An error occured');
				}
				)
		})
	});

	socket.on('deleteTaskBoard', (boardIdAndUser) => {
		const board_id = boardIdAndUser.board_id;
		const username = boardIdAndUser.username;
		const teamId = boardIdAndUser.teamId;

		pool.getConnection((err, conn) => {
			if (err) {
				socket.emit('error', { error: JSON.stringify(err) });
			}
			db.startTransaction(conn)
				.then(status => {
					return getTasksChecklistItemsForBoard({ connection: status.connection, params: [board_id] });
				}
				)
				.then(status => {
					if (status.result.length === 0)
						return Promise.resolve(status);

					const placeHolder = new Array(status.result.length).fill('?').join(',');
					const DELETE_TASKS_CHECKLISTS = `delete from task_checklist where task_id in (${placeHolder})`;

					const deleteTasksChecklists = db.mkQuery(DELETE_TASKS_CHECKLISTS);

					const taskIds = [];
					status.result.forEach(v => {
						taskIds.push(v.task_id);
					})
					return deleteTasksChecklists({ connection: status.connection, params: [taskIds] });
				})
				.then(status => {
					return deleteTasksByBoard({ connection: status.connection, params: [board_id] })
				})
				.then(status => {
					return deleteTaskBoard({ connection: status.connection, params: [board_id] });
				})
				.then(db.passthru, db.logError)
				.then(db.commit, db.rollback)
				.then(status => {
					socket.emit('success', 'You deleted task board');
					socket.to(teamId).emit('success', `${username} from team ${teamId} deleted task board`);
				}, status => {
					socket.emit('error', 'An error occured');
				}
				)
		})
	});

	socket.on('deleteTask', (taskIdAndUser) => {
		const taskId = taskIdAndUser.taskId;
		const username = taskIdAndUser.username;
		const teamId = taskIdAndUser.teamId;

		pool.getConnection((err, conn) => {
			if (err) {
				socket.emit('error', { error: JSON.stringify(err) });
			}

			db.startTransaction(conn)
				.then(status => {
					return deleteChecklist({ connection: status.connection, params: [taskId] });
				})
				.then(status => {
					return deleteTask({ connection: status.connection, params: [taskId] });
				})
				.then(db.passthru, db.logError)
				.then(db.commit, db.rollback)
				.then(status => {
					socket.emit('success', 'You deleted task');
					socket.to(teamId).emit('success', `${username} from team ${teamId} deleted task`);
				},
					status => {
						socket.emit('error', 'An error occured');
					}
				)
				.finally(() => { conn.release() });
		})
	});

	socket.on('createTask', (taskAndUser) => {
		const task = taskAndUser.task;
		const username = taskAndUser.username;
		const teamId = taskAndUser.teamId;

		pool.getConnection((err, conn) => {
			if (err) {
				socket.emit('error', { error: JSON.stringify(err) });
			}

			db.startTransaction(conn)
				.then(status => {
					const params = [task.title, task.description, task.status, task.board_id, username];

					return addTask({ connection: status.connection, params });
				})
				.then(getAddedTaskId)
				.then(status => {
					if (task.checkList.length === 0)
						return Promise.resolve(status);
					const newTaskId = status.result[0].task_id;
					const taskChecklist = task.checkList.map(v => {
						return [newTaskId, v.list_item, v.completed]
					})
					return addChecklistForTask({
						connection: status.connection,
						params: [taskChecklist]
					})
				})
				.then(db.passthru, db.logError)
				.then(db.commit, db.rollback)
				.then(status => {
					socket.emit('success', 'You created task');
					socket.to(teamId).emit('success', `${username} from ${teamId} created task`);
				},
					status => {
						socket.emit('error', 'An error occured');
					}
				)
				.finally(() => { conn.release() });
		})
	});

	socket.on('updateTaskStatus', (taskAndStatusAndUser) => {
		const updatedStatus = taskAndStatusAndUser.updatedStatus;
		const taskId = taskAndStatusAndUser.taskId;
		const username = taskAndStatusAndUser.username;
		const teamId = taskAndStatusAndUser.teamId;

		updateTaskStatus([updatedStatus, taskId])
			.then(result => {
				socket.emit('success', 'You updated task status');
				socket.to(teamId).emit('success', `${username} from ${teamId} updated task status`);
			})
			.catch(error => {
				socket.emit('error', { error: JSON.stringify(error) });
			})
	})

	socket.on('updateTaskDetails', (updatedTaskAndUser) => {
		const task = updatedTaskAndUser.updatedTask;
		const username = updatedTaskAndUser.username;
		const teamId = updatedTaskAndUser.teamId;

		let timestamp;

		if (!task.due_date)
			timestamp = null;
		else
			timestamp = new Date(task.due_date).toISOString().slice(0, 19).replace('T', ' ');;

		pool.getConnection((err, conn) => {
			if (err) {
				socket.emit('error', { error: JSON.stringify(err) });
			}

			db.startTransaction(conn)
				.then(status => {
					const params = [task.title, task.description, task.assigned_to, timestamp, task.task_id];

					return updateTaskDetails({ connection: status.connection, params });
				})
				.then(status => {
					return deleteChecklist({ connection: status.connection, params: [task.task_id] });
				})
				.then(status => {
					if (task.checklist.length === 0)
						return Promise.resolve(status);
					const taskChecklist = task.checklist.map(v => {
						return [task.task_id, v.list_item, v.completed]
					})
					return addChecklistForTask({
						connection: status.connection,
						params: [taskChecklist]
					})
				})
				.then(db.passthru, db.logError)
				.then(db.commit, db.rollback)
				.then(status => {
					socket.emit('success', 'You updated task details');
					socket.to(teamId).emit('success', `${username} from ${teamId} updated task details`);
				},
					status => {
						socket.emit('error', 'An error occured');
					}
				)
				.finally(() => { conn.release() });
		})
	});

	socket.on('leftRoom', (userAndTeam) => {
		const username = userAndTeam.username;
		const teamId = userAndTeam.teamId;

		socket.to(teamId).emit('leftRoom', `${username} has left room ${teamId}`);
		socket.leave(teamId);
	})
})

//No need authorization/authentication
app.post('/api/users', multipart.single('profilePic'), (req, res) => {
	pool.getConnection((err, conn) => {
		if (err)
			return res.status(500).json({ error: JSON.stringify(err) });

		db.startTransaction(conn)
			.then(status => {
				const params = [req.body.username, req.body.password, req.body.email, parseInt(req.body.teamId), req.file.filename, JSON.stringify(grants)];

				return createUser({ connection: status.connection, params })
			})
			.then(status => {
				return new Promise((resolve, reject) => {
					fs.readFile(req.file.path, (err, imgFile) => {
						if (err)
							return reject({ connection: status.connection, error: err });
						const params = {
							Bucket: 'free-images',
							Key: `profiles/${req.file.filename}`,
							Body: imgFile,
							ACL: 'public-read',
							ContentType: req.file.mimetype
						}
						s3.putObject(params, (err, result) => {
							if (err)
								return reject({ connection: status.connection, error: err });
							resolve({ connection: status.connection, result });
						})
					})
				})
			})
			.then(db.passthru, db.logError)
			.then(db.commit, db.rollback)
			.then(status => {
				fs.unlink(req.file.path, () => {
					res.status(201).json({ message: 'Created user' })
				});
			},
				status => {
					res.status(400).json({ message: `Error ${status.error}` });
				}
			)
			.finally(() => { conn.release() });
	})
})

//No need authorization/authentication as this is for create user function
app.get('/api/teams', (req, res) => {
	getAllTeams()
		.then(result => {
			res.status(200).json(result);
		})
		.catch(error => {
			res.status(500).json({ error: JSON.stringify(error) });
		})
})

//Token management: delete expired token
app.delete('/api/jwt/:id', (req, res) => {
	const tokenStr = req.params.id;

	client.db('projectmanagement').collection('jwt_tokens').deleteOne({ jwt: tokenStr })
		.then(result => {
			res.status(200).json(result);
		})
		.catch(error => {
			res.status(500).json({ error: JSON.stringify(error) });
		})
})

//Protected end-point
app.get('/api/users/:id',
	(req, res, next) => {
		const authorization = req.get('Authorization');

		//console.info('authorization', authorization);
		if (!(authorization && authorization.startsWith('Bearer ')))
			return res.status(403).json({ message: 'not authorized' });

		const tokenStr = authorization.substring('Bearer '.length);

		client.db('projectmanagement').collection('jwt_tokens').find({ jwt: tokenStr })
			.toArray()
			.then(result => {
				if (result.length > 0) {
					//console.info('found token');
					//req.jwt = result[0].token;
					//check if token is still valid i.e. expired or not
					//token undefined if expired
					req.jwt = jwt.verify(tokenStr, 'SECRET');
				}
				else {
					//console.info('token not found');
					req.jwt = jwt.verify(tokenStr, 'SECRET');

					client.db('projectmanagement').collection('jwt_tokens').insertOne({
						name: req.jwt.sub,
						jwt: tokenStr,
						token: req.jwt
					})
				}
			})
			.then(() =>
				next()
			)
			.catch(e => {
				return res.status(401).json({ message: e });
			})
	},
	(req, res) => {
		const username = req.params.id;
		getUserProfile([username])
			.then(result => {
				res.status(200).json(result[0]);
			})
			.catch(error => {
				res.status(500).json({ error: JSON.stringify(error) });
			})
	})

//Protected end-point
app.put('/api/users/:id', multipart.single('profilePic'),
	(req, res, next) => {
		const authorization = req.get('Authorization');

		//console.info('authorization', authorization);
		if (!(authorization && authorization.startsWith('Bearer ')))
			return res.status(403).json({ message: 'not authorized' });

		const tokenStr = authorization.substring('Bearer '.length);

		client.db('projectmanagement').collection('jwt_tokens').find({ jwt: tokenStr })
			.toArray()
			.then(result => {
				if (result.length > 0) {
					//console.info('found token');
					req.jwt = result[0].token;
					return next();
				}
				else {
					//console.info('token not found');
					req.jwt = jwt.verify(tokenStr, 'SECRET');

					client.db('projectmanagement').collection('jwt_tokens').insertOne({
						name: req.jwt.sub,
						jwt: tokenStr,
						token: req.jwt
					})
						.then(() => next())
						.catch(e => {
							return res.status(401).json({ message: 'invalid token' });
						})
				}
			})
	},
	(req, res) => {
		const username = req.params.id;

		pool.getConnection((err, conn) => {
			if (err)
				return res.status(500).json({ error: JSON.stringify(err) });

			db.startTransaction(conn)
				.then(status => {
					const params = [req.body.password, req.body.email, req.file.filename, username];
					return updateUserProfile({ connection: status.connection, params });
				})
				.then(status => {
					return new Promise((resolve, reject) => {
						fs.readFile(req.file.path, (err, imgFile) => {
							if (err)
								return reject({ connection: status.connection, error: err });
							const params = {
								Bucket: 'free-images',
								Key: `profiles/${req.file.filename}`,
								Body: imgFile,
								ACL: 'public-read',
								ContentType: req.file.mimetype
							}
							s3.putObject(params, (err, result) => {
								if (err)
									return reject({ connection: status.connection, error: err });
								resolve({ connection: status.connection, result });
							})
						})
					})
				})
				.then(status => {
					//delete previous profile pic
					return new Promise((resolve, reject) => {
						const params = {
							Bucket: 'free-images',
							Key: `profiles/${req.body.currentProfilePic}`
						}
						s3.deleteObject(params, (err, result) => {
							if (err)
								reject({ connection: status.connection, error: err });
							resolve({ connection: status.connection, result });
						});
					})
				})
				.then(db.passthru, db.logError)
				.then(db.commit, db.rollback)
				.then(status => {
					fs.unlink(req.file.path, () => {
						res.status(201).json({ updated_profile_pic_url: req.file.filename });
					});
				},
					status => {
						res.status(400).json({ message: `Error ${status.error}` });
					}
				)
				.finally(() => { conn.release() });
		})
	})

//Protected end-point
app.get('/api/users/team/:id',
	(req, res, next) => {
		const authorization = req.get('Authorization');

		//console.info('authorization', authorization);
		if (!(authorization && authorization.startsWith('Bearer ')))
			return res.status(403).json({ message: 'not authorized' });

		const tokenStr = authorization.substring('Bearer '.length);

		client.db('projectmanagement').collection('jwt_tokens').find({ jwt: tokenStr })
			.toArray()
			.then(result => {
				if (result.length > 0) {
					//console.info('found token');
					req.jwt = result[0].token;
					return next();
				}
				else {
					//console.info('token not found');
					req.jwt = jwt.verify(tokenStr, 'SECRET');

					client.db('projectmanagement').collection('jwt_tokens').insertOne({
						name: req.jwt.sub,
						jwt: tokenStr,
						token: req.jwt
					})
						.then(() => next())
						.catch(e => {
							return res.status(401).json({ message: 'invalid token' });
						})
				}
			})
	},
	(req, res) => {
		const teamId = req.params.id;
		const pics = [{ username: 'unassigned', profile_pic_url: 'default.png' }];
		getProfilePicsForTeam([teamId])
			.then(result => {
				result.forEach(v => {
					pics.push(v)
				})
				res.status(200).json(pics);
			})
			.catch(error => {
				res.status(500).json(error);
			})
	})

testConns(loadedConfigs)
	.then(result => {
		http.listen(PORT, () => {
			console.info(`Application started on port ${PORT} at ${new Date()}`);
		})
	})
	.catch(error => {
		console.info('error connecting...', error);
		process.exit(-1);
	})	