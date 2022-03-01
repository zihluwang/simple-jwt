## Simple JWT

该类库对 `com.auth0:java-jwt` 进行了简单的封装，以便于你可以在几乎不进行配置的情况下就能轻松使用 `JSON Web Token` 。

通过该类库的 `cn.vorbote.simplejwt.AccessKeyUtil` 类，完成了 JWT 必须的密钥和签发者之后便可以使用类中的各种简易方法来创建 
`JSON Web Token`。

> 该库现在处于 **_ALPHA_** 测试中，如果您想帮助我们测试，您可以克隆此库并使用 **maven** 或 **gradle** 将其构建到您的本地存储库。如果您在
> 使用过程中发现任何错误或有任何疑问，请随时通过提交 **Issues** 与我们描述你遇到的情况。如果你有能力修复或自行改进，我们也欢迎您的 
> **Pull Request**。