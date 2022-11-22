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

  return [201, newUser];
};

const userLoginService = async (email, password) => {
  const user = users.find((element) => element.email === email);

  if (!user) {
    return [401, { message: "Email ou senha inválidos" }];
  }

  const passwordMatch = await compare(password, user.password);

  if (!passwordMatch) {
    return [401, { message: "Email ou senha inválidos" }];
  }

  const token = jwt.sign({ email }, process.env.SECRET_KEY, {
    expiresIn: "24h",
    subject: user.uuid,
  });

  return [200, { token: token }];
};

const retrieveUserService = (request) => {
  const authToken = request.headers.authorization;
  const { uuid, createdOn, updatedOn, name, email, isAdm } = users[0];
  const newUser = {
    uuid: uuid,
    createdOn: createdOn,
    updatedOn: updatedOn,
    name: name,
    email: email,
    isAdm: isAdm,
  };

  if (!authToken) {
    return [401, { message: "Missing authorization token." }];
  }

  const token = authToken.split(" ")[1];

  const [status, user] = verify(
    token,
    process.env.SECRET_KEY,
    (error, decoded) => {
      if (error) {
        return [401, { message: error.message }];
      }
      return [200, newUser];
    }
  );

  return [status, user];
};

const userUpdadeService = (index, body) => {
  const newUser = { ...users[index], ...body, updatedOn: new Date() };
  users[index] = newUser;
  return [204, newUser];
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

const verifyIsAdmPath = (request, response, next) => {
  const id = request.params.id;
  const [status, user] = retrieveUserService(request);

  if (status >= 400) {
    return response.status(status).json(user);
  }

  const userUuidExist = users.find((element) => element.uuid === id);
  const userIndex = users.findIndex((element) => element.uuid === id);

  if (!userUuidExist) {
    return response.status(404).json("User not found");
  } else if (!userUuidExist.isAdm) {
    return response.status(403).json({ message: "missing admin permissions" });
  }

  request.userIndex = userIndex;

  return next();
};

// Controllers
const listUserController = (request, response) => {
  return response.status(200).json(users);
};

const createUserController = async (request, response) => {
  const { email, name, password, isAdm } = request.body;

  const [status, user] = await createUserService(email, name, password, isAdm);

  return response.status(status).json(user);
};

const userLoginController = async (request, response) => {
  const { email, password } = request.body;

  const [status, token] = await userLoginService(email, password);

  return response.status(status).json(token);
};

const retrieveUserController = (request, response) => {
  const [status, user] = retrieveUserService(request);
  return response.status(status).json(user);
};

const userUpdadeController = (request, response) => {
  const i = request.userIndex;
  const [status, user] = userUpdadeService(i, request.body);
  return response.status(status).json(user);
};

const userDeleteController = (request, response) => {
  const i = request.userIndex;

  const [status, message] = userDeleteService(i);

  return response.status(status).json(message);
};

app.get("/users", listUserController);

app.post("/users", verifyEmailExistsMiddleware, createUserController);

app.post("/login", userLoginController);

app.get("/users/profile", retrieveUserController);

app.patch("/users/:id", verifyIsAdmPath, userUpdadeController);

app.delete("/users/:id", verifyIsAdmPath, userDeleteController);

app.listen(PORT, () => {
  console.log(`App rodando na porta ${PORT}`);
});

export default app;
