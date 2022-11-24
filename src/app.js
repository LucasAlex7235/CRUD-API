import express, { request } from "express";
import users from "./database";
import { v4 as uuidv4 } from "uuid";
import * as bcrypt from "bcryptjs";
import { hash, compare } from "bcryptjs";
import jwt, { verify } from "jsonwebtoken";
import "dotenv/config";

const app = express();
app.use(express.json());

const PORT = process.env.PORT;

// Services
const createUserService = async (email, name, password, isAdm) => {
  const hashedPassword = await hash(password, 10);

  const newUser = {
    uuid: uuidv4(),
    createdOn: new Date(),
    updatedOn: new Date(),
    name,
    email,
    password: hashedPassword,
    isAdm,
  };
  users.push(newUser);

  const { uuid, createdOn, updatedOn } = newUser;

  const userWithoutPassword = {
    uuid: uuid,
    createdOn: createdOn,
    updatedOn: updatedOn,
    name: name,
    email: email,
    isAdm: isAdm,
  };

  return [201, userWithoutPassword];
};

const userLoginService = async ({ token }) => {
  return [200, { token: token }];
};

const retrieveUserService = ({
  uuid,
  createdOn,
  updatedOn,
  name,
  email,
  isAdm,
}) => {
  const userProfile = {
    uuid: uuid,
    createdOn: createdOn,
    updatedOn: updatedOn,
    name: name,
    email: email,
    isAdm: isAdm,
  };

  return [200, userProfile];
};

const listUserService = ({ isAdm }) => {
  if (isAdm) {
    const listUsersNotPassword = users.map((user) => {
      const newUser = {
        uuid: user.uuid,
        createdOn: user.createdOn,
        updatedOn: user.updatedOn,
        name: user.name,
        email: user.email,
        isAdm: user.isAdm,
      };
      return newUser;
    });

    return [200, listUsersNotPassword];
  }
  return [403, { message: "missing admin permissions" }];
};

const userUpdadeService = ({ params, user, body }) => {
  const { id } = params;
  const { uuid, isAdm } = user;
  const userIndex = users.findIndex((user) => user.uuid === id);

  if (userIndex === -1) {
    return [404, { message: "User not found" }];
  } else if (isAdm) {
    const newUser = {
      uuid: body.uuid ? body.uuid : user.uuid,
      createdOn: body.createdOn ? body.createdOn : user.createdOn,
      updatedOn: body.updatedOn ? body.updatedOn : user.updatedOn,
      name: body.name ? body.name : user.name,
      email: body.email ? body.email : user.email,
      isAdm: body.isAdm ? body.isAdm : user.isAdm,
    };
    const updateUser = { ...users[userIndex], ...body, updatedOn: new Date() };
    users[userIndex] = updateUser;
    return [200, newUser];
  } else if (!isAdm && uuid === id) {
    const newUser = {
      uuid: body.uuid ? body.uuid : user.uuid,
      createdOn: body.createdOn ? body.createdOn : user.createdOn,
      updatedOn: body.updatedOn ? body.updatedOn : user.updatedOn,
      name: body.name ? body.name : user.name,
      email: body.email ? body.email : user.email,
      isAdm: body.isAdm ? body.isAdm : user.isAdm,
    };
    const updateUser = { ...users[userIndex], ...body, updatedOn: new Date() };
    users[userIndex] = updateUser;
    return [200, newUser];
  }
};

const userDeleteService = (index) => {
  users.splice(users.indexOf(index), 1);

  return [204, { message: "successfully deleted user" }];
};

//Middleware

const verifyEmailExistsMiddleware = (request, response, next) => {
  const { email } = request.body;
  const userArealdyExists = users.find((user) => user.email === email);

  if (userArealdyExists) {
    return response
      .status(409)
      .json({ message: "This email address is already being used" });
  }

  return next();
};

const verifyUserExist = async (request, response, next) => {
  const { email, password } = request.body;

  const user = users.find((element) => element.email === email);

  if (!user) {
    return response.status(401).json({
      message: "Email ou senha inválidos",
    });
  }

  const passwordMatch = await compare(password, user.password);

  if (!passwordMatch) {
    return response.status(401).json({
      message: "Email ou senha inválidos",
    });
  }

  const token = jwt.sign(
    {
      name: user.name,
      email: user.email,
      isAdm: user.isAdm,
      createdOn: user.createdOn,
      updatedOn: user.updatedOn,
    },
    process.env.SECRET_KEY,
    {
      expiresIn: "24h",
      subject: user.uuid,
    }
  );

  request.token = token;

  return next();
};

const authorizationVerify = (request, response, next) => {
  const authToken = request.headers.authorization;

  if (!authToken) {
    return response
      .status(401)
      .json({ message: "Missing authorization token." });
  }
  const token = authToken.split(" ")[1];

  return verify(token, process.env.SECRET_KEY, (error, decoded) => {
    if (error) {
      return response.status(401).json({ message: error.message });
    }

    request.user = {
      uuid: decoded.sub,
      name: decoded.name,
      email: decoded.email,
      isAdm: decoded.isAdm,
      createdOn: decoded.createdOn,
      updatedOn: decoded.updatedOn,
    };

    return next();
  });
};

const verifyIsAdm = (request, response, next) => {
  const id = request.params.id;
  const { isAdm, uuid } = request.user;

  if (!isAdm && uuid !== id) {
    return response.status(403).json({
      message: "missing admin permissions",
    });
  }

  return next();
};

// Controllers
const listUserController = (request, response) => {
  const [status, data] = listUserService(request.user);
  return response.status(status).json(data);
};

const createUserController = async (request, response) => {
  const { email, name, password, isAdm } = request.body;

  const [status, user] = await createUserService(email, name, password, isAdm);

  return response.status(status).json(user);
};

const userLoginController = async (request, response) => {
  const [status, token] = await userLoginService(request);
  return response.status(status).json(token);
};

const retrieveUserController = (request, response) => {
  const [status, user] = retrieveUserService(request.user);
  return response.status(status).json(user);
};

const userUpdadeController = (request, response) => {
  const [status, user] = userUpdadeService(request);
  return response.status(status).json(user);
};

const userDeleteController = (request, response) => {
  const i = request.userIndex;
  const [status, message] = userDeleteService(i);

  return response.status(status).json(message);
};

app.get("/users", authorizationVerify, listUserController);

app.post("/users", verifyEmailExistsMiddleware, createUserController);

app.post("/login", verifyUserExist, userLoginController);

app.get("/users/profile", authorizationVerify, retrieveUserController);

app.patch("/users/:id", authorizationVerify, verifyIsAdm, userUpdadeController);

app.delete(
  "/users/:id",
  authorizationVerify,
  verifyIsAdm,
  userDeleteController
);

app.listen(PORT, () => {
  console.log(`App rodando na porta ${PORT}`);
});

export default app;
