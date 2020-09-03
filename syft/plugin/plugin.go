package plugin

import (
	"fmt"
	"os/exec"

	"github.com/hashicorp/go-plugin"
)

var plugins = map[int]plugin.PluginSet{
	1: {
		TypeCataloger.String(): &CatalogerPlugin{},
	},
}

type Config struct {
	Name    string
	Type    Type
	Command string
	Args    []string
	Env     []string
	//Sha256  []byte
}

type Plugin struct {
	Config       Config
	clientConfig *plugin.ClientConfig
	client       *plugin.Client
}

func NewPlugin(config Config) Plugin {
	cmd := exec.Command(config.Command, config.Args...)
	cmd.Env = append(cmd.Env, config.Env...)

	//secureConfig := &plugin.SecureConfig{
	//	Checksum: config.Sha256,
	//	Hash:     sha256.New(),
	//}

	clientConfig := &plugin.ClientConfig{
		HandshakeConfig:  config.Type.HandshakeConfig(),
		VersionedPlugins: plugins,
		//SecureConfig:     secureConfig,
		Cmd: cmd,
		AllowedProtocols: []plugin.Protocol{
			plugin.ProtocolGRPC,
		},
	}

	return Plugin{
		Config:       config,
		clientConfig: clientConfig,
	}
}

func (p Plugin) Start() (interface{}, error) {
	if p.client != nil {
		return nil, fmt.Errorf("plugin already started")
	}

	// start the plugin in a sub process
	p.client = plugin.NewClient(p.clientConfig)

	// connect to the sub process via RPC
	rpcClient, err := p.client.Client()
	if err != nil {
		return nil, err
	}

	// fetch the plugin object meeting the requested interface
	raw, err := rpcClient.Dispense(p.Config.Type.String())
	if err != nil {
		return nil, err
	}

	return raw, nil
}

func (p Plugin) Stop() error {
	if p.client == nil {
		return fmt.Errorf("plugin has not been started")
	}
	p.client.Kill()
	return nil
}