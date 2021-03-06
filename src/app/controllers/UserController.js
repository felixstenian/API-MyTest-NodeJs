import * as Yup from "yup";
import crypto from "crypto";

import User from "../models/User";
import File from "../models/File";

import Mail from "../../lib/Mail";

class UserController {
  async store(req, res) {
    const schema = Yup.object().shape({
      name: Yup.string().required(),
      user_name: Yup.string().required(),
      email: Yup.string()
        .email()
        .required(),
      password: Yup.string()
        .required()
        .min(6)
        .matches(/[a-z]/)
        .matches(/[A-Z]/)
    });

    // Validação de schema
    if (!(await schema.isValid(req.body))) {
      return res.status(400).json({ error: "Falha na Validação." });
    }
    // Verificando email e nome de usuário são únicos
    const emailExists = await User.findOne({
      where: { email: req.body.email }
    });

    const userNameExists = await User.findOne({
      where: { user_name: req.body.user_name }
    });

    if (emailExists) {
      return res.status(400).json({ error: "Email já existe" });
    }

    if (userNameExists) {
      return res.status(400).json({ error: "User name já existe" });
    }

    // Criando novo usuário
    const { id, name, user_name, email, avatar, active } = await User.create(
      req.body
    );

    //Hash para envio de link na ativação de contas

    const secret = "mytest";
    const hash = crypto.createHmac("sha256", secret).digest("hex");

    const id_hash = id + "$" + hash;

    await Mail.sendMail({
      to: `${user_name} <${email}>`,
      subject: "Confirmar Cadastro",
      template: "cadastro",
      context: {
        user_name,
        id_hash
      }
    });

    return res.json({
      id,
      name,
      user_name,
      email,
      avatar,
      active
    });
  }

  async update(req, res) {
    const schema = Yup.object().shape({
      name: Yup.string(),
      user_name: Yup.string(),
      email: Yup.string().email(),
      oldPassword: Yup.string().min(6),
      password: Yup.string()
        .min(6)
        .matches(/[a-z]/)
        .matches(/[A-Z]/)
        .required()
        .when("oldPassword", (oldPassword, field) =>
          oldPassword ? field.required() : field
        ),
      confirmPassword: Yup.string().when("password", (password, field) =>
        password ? field.required().oneOf([Yup.ref("password")]) : field
      )
    });

    // Validação de schema
    if (await schema.isValid(req.body)) {
      return res.status(400).json({ error: "Falha na Validação." });
    }

    const { user_name, email, oldPassword } = req.body;

    const user = await User.findByPk(req.userId);

    // Verificando email
    if (email != user.email) {
      const emailExists = await User.findOne({ where: { email } });

      if (emailExists) {
        return res.status(400).json({ error: "Email já existe" });
      }
    }

    // Verificando nome de usuário
    if (user_name != user.user_name) {
      const userNameExists = await User.findOne({ where: { user_name } });

      if (userNameExists) {
        return res.status(400).json({ error: "User name já existe" });
      }
    }

    if (oldPassword && !(await user.checkPassword(oldPassword))) {
      return res.status(401).json({ error: "Password anterior incorreto." });
    }

    await user.update(req.body);

    const { id, name, avatar } = await User.findByPk(req.userId, {
      include: [
        {
          model: File,
          as: "avatar",
          attributes: ["id", "path", "url"]
        }
      ]
    });

    return res.json({
      id,
      name,
      user_name,
      email,
      avatar
    });
  }
}

export default new UserController();
