import "dotenv/config";

import express from "express";
import "express-async-errors";
import cors from "cors";
import Youch from "youch";
import * as Sentry from "@sentry/node";
import path from "path";

import routes from "./router";
import sentryConfig from "./config/sentry";

import "./database";

class App {
  constructor() {
    this.server = express();

    Sentry.init(sentryConfig);

    this.server.use(Sentry.Handlers.requestHandler());
    this.middlewares();
    this.routes();
    this.exceptionHandler();
  }

  middlewares() {
    this.server.use(
      "/files",
      express.static(path.resolve(__dirname, "..", "temp", "uploads"))
    );
    this.server.use(express.json());
    this.server.use(cors());
  }

  routes() {
    this.server.use(routes);
    this.server.use(Sentry.Handlers.errorHandler());
  }

  exceptionHandler() {
    this.server.use(async (err, req, res, next) => {
      if (process.env.NODE_ENV === "development") {
        const errors = await new Youch(err, req).toJSON();

        return res.status(500).json(errors);
      }

      return res.status(500).json({ error: "Erro no Servidor" });
    });
  }
}

export default new App().server;
