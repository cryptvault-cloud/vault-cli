package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"path"
	"strings"

	_ "embed"

	client "github.com/cryptvault-cloud/api"
	"github.com/cryptvault-cloud/helper"
	"github.com/cryptvault-cloud/vault-cli/logger"
	"github.com/urfave/cli/v3"
	"github.com/vektah/gqlparser/v2/gqlerror"
)

const (
	CliLogLevel                   = "logLevel"
	CliServerUrl                  = "serverUrl"
	CliSaveToFile                 = "should_save_to_file"
	CliInitVaultId                = "vaultId"
	CliInitVaultName              = "vaultName"
	CliCreateVaultVaultName       = "vaultName"
	CliCreateVaultVaultToken      = "vaultToken"
	CliAuthTokenPrivateKey        = "authTokenPrivateKey"
	CliAuthTokenVaultId           = "authTokenVaultId"
	CliProtectedHandlerKey        = "handlerkey"
	CliProtectedVaultId           = "vaultid"
	CliAddValueName               = "name"
	CliUpdateValueName            = "name"
	CliAddIdentityName            = "name"
	CliAddIdentityPublicKey       = "public_key"
	CliUpdateIdentityName         = "name"
	CliUpdateIdentityId           = "id"
	CliAddIdentityRights          = "rights"
	CliUpdateIdentityRightsAdd    = "rights-add"
	CliUpdateIdentityRightsRemove = "rights-remove"

	CliGetIdentityId              = "id"
	CliGetValueName               = "name"
	CliAddValuePassframe          = "passframe"
	CliUpdateValuePassframe       = "passframe"
	CliAddValueType               = "type"
	CliUpdateValueType            = "type"
	CliSaveFilePath               = "save_file_path"
	CliDeleteIdentityId           = "id"
	CliDeleteValueName            = "name"
	CliAddIdentityLocalPrivateKey = "private_key"
	CliAddIdentityLocalName       = "name"
	CliCreateIdentityLocalName    = "name"

	App = "VAULT_CLI"
)

func getFlagEnvByFlagName(flagName string) string {
	return fmt.Sprintf("%s_%s", App, strings.ToUpper(flagName))
}

func cliRunner() {

	runner := Runner{}

	app := &cli.Command{
		EnableShellCompletion: true,
		Usage:                 "vault-cli",
		Version:               fmt.Sprintf("%s [%s]", version, commit),
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    CliLogLevel,
				Sources: cli.EnvVars(getFlagEnvByFlagName(CliLogLevel)),
				Value:   "info",
				Usage:   "Loglevel debug, info, warn, error",
			},
			&cli.StringFlag{
				Name:    CliServerUrl,
				Sources: cli.EnvVars(getFlagEnvByFlagName(CliServerUrl)),
				Value:   "https://api.cryptvault.cloud/query",
				Usage:   "Endpoint where api is running",
			},
			&cli.BoolFlag{
				Name:    CliSaveToFile,
				Sources: cli.EnvVars(getFlagEnvByFlagName(CliSaveToFile)),
				Usage:   "Should created information be saved to a folder structure",
				Value:   true,
			},
			&cli.StringFlag{
				Name:    CliSaveFilePath,
				Sources: cli.EnvVars(getFlagEnvByFlagName(CliSaveFilePath)),
				Value:   "./.cryptvault/",
				Usage:   "Path to folder where to save all created data",
			},
		},
		Before: runner.Before,
		Commands: []*cli.Command{
			{
				Name:  "local",
				Usage: "To handle with local files",
				Commands: []*cli.Command{
					{
						Name:   "init",
						Usage:  "create a local workspace for an already exist Vault",
						Action: runner.init_vault,
						Flags: []cli.Flag{
							&cli.StringFlag{
								Name:     CliInitVaultName,
								Aliases:  []string{"vault-name"},
								Required: true,
								Usage:    "Name of the new Vault to init",
							},
							&cli.StringFlag{
								Name:     CliInitVaultId,
								Aliases:  []string{"id"},
								Required: true,
								Usage:    "Id of the vault",
							},
						},
					},

					{
						Name: "add",
						Commands: []*cli.Command{
							{
								Name:        "identity-by-private-key",
								Usage:       "add a identity local to the file structure. ",
								Description: "Useful if an identity was create by some one else, but you will use it.",
								Action:      runner.add_identity,
								Flags: []cli.Flag{
									&cli.StringFlag{
										Name:     CliAddIdentityLocalPrivateKey,
										Aliases:  []string{"key"},
										Required: true,
										Usage:    "Private Key of identity",
									},
									&cli.StringFlag{
										Name:  CliAddIdentityLocalName,
										Usage: "Name of identity if not set it will try query from cryptvault (require min right (r)IDENTITY.>)",
										Value: "",
									},
								},
							},
						},
					},
					{
						Name: "create",
						Commands: []*cli.Command{
							{
								Name:        "identity",
								Usage:       "create a new identity key pair without register at vault.cloud. ",
								Description: "Useful if your identity will register by an other team so you can send them you public key.",
								Action:      runner.create_local_identity,
								Flags: []cli.Flag{
									&cli.StringFlag{
										Name:     CliCreateIdentityLocalName,
										Sources:  cli.EnvVars(getFlagEnvByFlagName(CliCreateIdentityLocalName)),
										Usage:    "Name of identity ",
										Value:    "",
										Required: true,
									},
								},
							},
						},
					},
					{
						Name:   "list-vault",
						Usage:  "All local available Vaults",
						Action: runner.LocalListVault,
					},
					{
						Name:   "selected-vault",
						Usage:  "Which vault is current selected",
						Action: runner.LocalSelectedVault,
					},
					{
						Name:   "select-vault",
						Usage:  "Set current selected vault",
						Action: runner.LocalSelectVault,
						Flags: []cli.Flag{
							&cli.StringFlag{
								Name:     "vault",
								Usage:    "The vaultname to set",
								Required: true,
							},
						},
					},
				},
			},
			{
				Name:   "create_vault",
				Usage:  "Create a new Vault",
				Action: runner.create_vault,
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:     CliCreateVaultVaultName,
						Sources:  cli.EnvVars(getFlagEnvByFlagName(CliCreateVaultVaultName)),
						Aliases:  []string{"vault-name"},
						Required: true,
						Usage:    "Name of the new Vault to init",
					},
					&cli.StringFlag{
						Name:     CliCreateVaultVaultToken,
						Sources:  cli.EnvVars(getFlagEnvByFlagName(CliCreateVaultVaultToken)),
						Aliases:  []string{"token"},
						Required: true,
						Usage:    "Token to verify vault generation is allowed",
					},
				},
			},
			GetProtectedCommand(&runner),
		},
	}
	if err := app.Run(context.Background(), os.Args); err != nil {
		if gqlErr, ok := err.(gqlerror.List); ok {
			for i, err := range gqlErr {
				fmt.Printf("Error %d:\n", i+1)
				fmt.Printf("Message: %s \n", err.Message)
				fmt.Print("Details: \n")
				for k, v := range err.Extensions {
					if v == "" {
						v = "-"
					}
					fmt.Printf("\t%s:  %s\n", k, v)
				}
			}
		} else {
			fmt.Println("Error:", err)
		}
	}
}

type Runner struct {
	api         client.ApiHandler
	fileHandler FileHandling
}

func (r *Runner) LocalListVault(ctx context.Context, c *cli.Command) error {
	vaults, err := r.fileHandler.AvailableVaults()
	if err != nil {
		return err
	}
	for _, v := range vaults {
		fmt.Println(v)
	}
	return nil
}

func (r *Runner) LocalSelectedVault(ctx context.Context, c *cli.Command) error {
	t, err := r.fileHandler.SelectedVault()
	if err != nil {
		return err
	}
	fmt.Println(string(t))
	return nil
}

func (r *Runner) LocalSelectVault(ctx context.Context, c *cli.Command) error {
	vaultName := c.String("vault")
	vaults, err := r.fileHandler.AvailableVaults()
	if err != nil {
		return err
	}
	if helper.Includes[string](vaults, func(s string) bool { return s == vaultName }) {
		return r.fileHandler.SaveTextToFile("/currentVault.txt", vaultName)
	} else {
		return fmt.Errorf("Vault not found... ")
	}
}

func (r *Runner) Before(ctx context.Context, c *cli.Command) (context.Context, error) {
	_, err := logger.Initialize(c.String(CliLogLevel))

	r.api = client.NewApi(c.String(CliServerUrl), http.DefaultClient)
	if c.Bool(CliSaveToFile) {
		r.fileHandler = &FileHandler{
			RootPath: c.String(CliSaveFilePath),
		}
		err = r.fileHandler.Init()
		if err != nil {
			return ctx, err
		}
	} else {
		r.fileHandler = &FileHandlerMock{}
	}

	return ctx, err
}

func (r *Runner) init_vault(ctx context.Context, c *cli.Command) error {
	vaultName := c.String(CliInitVaultName)
	vaultID := c.String(CliInitVaultId)
	var err error = nil
	err = errors.Join(r.fileHandler.SaveTextToFile("/currentVault.txt", vaultName), err)
	err = errors.Join(r.fileHandler.SaveTextToFile(fmt.Sprintf("%s/vaultId", vaultName), vaultID), err)
	if err != nil {
		return err

	}

	fmt.Println("Created folder Structure")
	return nil
}

func (r *Runner) create_local_identity(ctx context.Context, c *cli.Command) error {
	name := c.String(CliCreateIdentityLocalName)
	privKey, pubKey, err := r.api.GetNewIdentityKeyPair()
	if err != nil {
		return err
	}
	vaultName, err := r.fileHandler.SelectedVault()
	if err != nil {
		return err
	}
	vaultId, err := r.fileHandler.ReadTextFile(fmt.Sprintf("%s/vaultId", vaultName))
	if err != nil {
		return err
	}
	b64PubKey, err := helper.NewBase64PublicPem(pubKey)
	if err != nil {
		return err
	}
	identityId, err := b64PubKey.GetIdentityId(vaultId)
	if err != nil {
		return err
	}
	b64PrivKey, err := helper.GetB64FromPrivateKey(privKey)
	if err != nil {
		return err
	}

	err = errors.Join(r.fileHandler.SaveTextToFile(fmt.Sprintf("%s/identity/%s/key.pub", vaultName, name), string(b64PubKey)), err)
	err = errors.Join(r.fileHandler.SaveTextToFile(fmt.Sprintf("%s/identity/%s/key", vaultName, name), b64PrivKey), err)
	err = errors.Join(r.fileHandler.SaveTextToFile(fmt.Sprintf("%s/identity/%s/id", vaultName, name), identityId), err)
	if err != nil {
		return err
	}
	fmt.Printf("New Local identity created at %s\n", r.fileHandler.FullPath(fmt.Sprintf("%s/identity/%s", vaultName, name)))
	fmt.Printf("Your public key to share with someone who can add you to the cryptvault.cloud:\n\n%s\n", b64PubKey)
	return nil

}

func (r *Runner) add_identity(ctx context.Context, c *cli.Command) error {
	private_key_str := c.String(CliAddIdentityLocalPrivateKey)
	name := c.String(CliAddIdentityLocalName)
	key, err := helper.GetPrivateKeyFromB64String(private_key_str)
	if err != nil {
		return err
	}
	vaultName, err := r.fileHandler.SelectedVault()
	if err != nil {
		return err
	}
	vaultId, err := r.fileHandler.ReadTextFile(fmt.Sprintf("%s/vaultId", vaultName))
	if err != nil {
		return err
	}
	b64PubKey, err := helper.NewBase64PublicPem(&key.PublicKey)
	if err != nil {
		return err
	}
	identityId, err := b64PubKey.GetIdentityId(vaultId)
	if err != nil {
		return err
	}
	if name == "" {
		serverIdentity, err := r.api.GetProtectedApi(key, vaultId).GetIdentity(identityId)
		if err != nil {
			return err
		}
		name = *serverIdentity.Name
	}
	err = errors.Join(r.fileHandler.SaveTextToFile(fmt.Sprintf("%s/identity/%s/key.pub", vaultName, name), string(b64PubKey)), err)
	err = errors.Join(r.fileHandler.SaveTextToFile(fmt.Sprintf("%s/identity/%s/key", vaultName, name), private_key_str), err)
	err = errors.Join(r.fileHandler.SaveTextToFile(fmt.Sprintf("%s/identity/%s/id", vaultName, name), identityId), err)
	if err != nil {
		return err
	}
	return nil
}

func (r *Runner) create_vault(ctx context.Context, c *cli.Command) error {
	vaultName := c.String(CliCreateVaultVaultName)
	privKey, pubKey, vaultID, err := r.api.NewVault(vaultName, c.String(CliCreateVaultVaultToken))
	if err != nil {
		log.Println("hier", r.api)
		return err
	}

	b64PubKey, err := helper.GetB64FromPublicKey(pubKey)
	if err != nil {
		return err
	}
	b64PrivKey, err := helper.GetB64FromPrivateKey(privKey)
	if err != nil {
		return err
	}
	fmt.Printf("Vault with id:\t%s was created\n", vaultID)
	fmt.Printf("Folder %s was created\n", path.Join(c.String(CliSaveFilePath), vaultName))
	fmt.Printf("Operator identity was saved at %s\n", path.Join(c.String(CliSaveFilePath), vaultName, "operator"))
	fmt.Printf("Current selected Vault is set to %s", vaultName)

	err = errors.Join(r.fileHandler.SaveTextToFile("/currentVault.txt", vaultName), err)
	err = errors.Join(r.fileHandler.SaveTextToFile(fmt.Sprintf("%s/vaultId", vaultName), vaultID), err)
	err = errors.Join(r.fileHandler.SaveTextToFile(fmt.Sprintf("%s/operator/key.pub", vaultName), b64PubKey), err)
	err = errors.Join(r.fileHandler.SaveTextToFile(fmt.Sprintf("%s/operator/key", vaultName), b64PrivKey), err)
	return err

}
