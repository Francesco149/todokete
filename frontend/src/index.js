/* eslint semi: "error" */

import React from 'react';
import ReactDOM from 'react-dom';
import './index.css';
const compileExpressionBase = require('filtrex').compileExpression;

function compileExpression(x) {
  return compileExpressionBase(x, {
    customProp: (propertyName, get, obj) => {
      switch (propertyName.toLowerCase()) {
        case "urtickets":
          return (9015 in obj.items) ? obj.items[9015] : 0;
        case "stars":
          return (0 in obj.items) ? obj.items[0] : 0;
        default:
          return get(propertyName);
      }
    },
    extraFunctions: {
      hoursAgo: (x) => Date.now() - x * 3600000
    },
  });
}

function copyToClipboard(str) {
  const el = document.createElement('textarea');
  el.value = str;
  el.setAttribute('readonly', '');
  el.style.position = 'absolute';
  el.style.left = '-9999px';
  document.body.appendChild(el);
  const selected =
    document.getSelection().rangeCount > 0
      ? document.getSelection().getRangeAt(0)
      : false;
  el.select();
  el.setSelectionRange(0, 99999);
  document.execCommand('copy');
  document.body.removeChild(el);
  if (selected) {
    document.getSelection().removeAllRanges();
    document.getSelection().addRange(selected);
  }
}

const baseUrl = () => `http://${window.location.hostname}:6868`;
const textureUrl = (x) =>
  baseUrl() + `/texture?packName=${x.packName}&head=${x.head}`;

function htmlDecode(input) {
  var doc = new DOMParser().parseFromString(input, "text/html");
  return doc.documentElement.textContent;
}

class Todokete extends React.Component {
  constructor(props) {
    super(props);
    this.state = {
      accounts: [],
      items: [],
      filterText: "stars > 900",
      filter: compileExpression("stars > 900"),
      filterValid: true,
      loadedResults: 10,
      selected: null,
      mail: "",
      password: "",
      fetchingSifid: false,
      sifidData: null,
      archiveText: "archive",
      showArchived: 0,
    };
  }

  resetSelectedAccount() {
    this.setState({
      mail: "",
      password: "",
      sifidData: null,
      archiveText: "archive"
    });
  }

  fetchAccounts() {
    fetch(`http://${window.location.hostname}:6868/accounts`)
      .then(res => res.json())
      .then(data => this.setState({accounts: data}))
      .then(() => {
        fetch(`http://${window.location.hostname}:6868/items`)
        .then(res => res.json())
        .then(data => this.setState({items: data}));
      });
  }

  renderTexture(id) {
    if (!(id in this.state.items)) return;
    const x = this.state.items[id];
    let alt = '[' + id + '] ' + htmlDecode(x.name || "") +
      ': ' + htmlDecode(x.description || "");
    return x.packName && x.head ?
      <img src={textureUrl(x)} alt={alt} title={alt} /> : "";
  }

  mailChanged(ev) { this.setState({ mail: ev.target.value }); }
  passwordChanged(ev) { this.setState({ password: ev.target.value }); }

  linkSifid(account) {
    fetch(`http://${window.location.hostname}:6868` +
      `/link?id=${account.id}&mail=${this.state.mail}` +
      `&password=${this.state.password}`);
  }

  fetchSifid(account) {
    this.setState({ fetchingSifid: true });
    fetch(`http://${window.location.hostname}:6868/sifid` +
      ("sifidMail" in account ? `?mail=${account.sifidMail}` : ""))
    .then(res => {
      if (!res.ok) {
        throw Error(res.statusText);
      }
      return res.json();
    })
    .then(data => this.setState({
      sifidData: data,
      mail: data.mail,
      password: data.password,
    }))
    .catch(err => console.log(err))
    .finally(() => this.setState({ fetchingSifid: false }));
  }

  copySifid(account) {
    let data = this.state.sifidData;
    copyToClipboard(
      `email: ${data.mail}\r\n` +
      `password: ${data.password}\r\n` +
      `secret question: ${data.secretQuestion}\r\n` +
      `secret answer: ${data.secretAnswer}\r\n` +
      `date of birth: ` +
        `${data.birthYear}-${data.birthMonth}-${data.birthDay}\r\n\r\n` +
      `you can transfer the sif id to your own email if you wish so ` +
      `at this page https://www.sifid.net/recover/email`
    );
  }

  archive(account) {
    switch (this.state.archiveText) {
      case "archive":
        this.setState({archiveText: "are you sure?"});
        break;
      default:
        fetch(`http://${window.location.hostname}:6868/archive" +
          "?id=${account.id}`);
        this.resetSelectedAccount();
        break;
    }
  }

  renderSifid(account) {
    if (this.state.selected !== account.id) return "";
    if (account.sifidMail) {
      return (
        <div className="link-sifid">
        <input value={account.sifidMail} readOnly />
        <button className="left-button"
          onClick={() => this.archive(account)}>
          {this.state.archiveText}
        </button>
        <button onClick={() => this.copySifid(account)}
          disabled={this.state.fetchingSifid || !this.state.sifidData}>
          {this.state.fetchingSifid ? "fetching..." :
            this.state.sifidData ? "copy to clipboard" : "(can't fetch)"}
        </button>
        </div>
      );
    }
    return (
      <div className="link-sifid">
      <input type="text"
        onChange={(e) => this.mailChanged(e)}
        placeholder="email@example.com"
        value={this.state.mail} />
      <input type="password"
        onChange={(e) => this.passwordChanged(e)}
        placeholder="passw0rd"
        value={this.state.password} />
      <button
        className="left-button"
        onClick={() => this.fetchSifid(account)}
        disabled={this.state.fetchingSifid}
      >
        {this.state.fetchingSifid ? "fetching..." : "from database"}
      </button>
      <button onClick={() => this.linkSifid(account)}>link sifid</button>
      </div>
    );
  }

  accountClicked(account) {
    if (account.id !== this.state.selected) {
      this.resetSelectedAccount();
    }
    this.setState({selected: account.id});
    if ("sifidMail" in account && account.sifidMail !== null) {
      this.fetchSifid(account);
    }
  }

  renderAccount(account) {
    const selected = account.id === this.state.selected;
    return (
      <li
        key={account.id}
        onClick={() => this.accountClicked(account)}
        className={selected ?  "selected-account" : ""}
      >
        {selected ? <div className="top-left-text">{account.id}</div> : ""}
        {this.renderSifid(account)}
        <ul className="items">
          {Object.entries(account.items).map(([id, amount]) => {
            return (
              <li key={id}>
                {this.renderTexture(id)}
                <div className="item-amount">x{amount}</div>
              </li>
            );
          })}
        </ul>
      </li>
    );
  }

  filterChanged(ev) {
    try {
      this.setState({
        filterText: ev.target.value,
        filter: compileExpression(ev.target.value),
        filterValid: true,
        loadedResults: 10,
      });
    } catch (e) {
      this.setState({
        filterText: ev.target.value,
        filterValid: false,
      });
    }
  }

  loadMore() {
    this.setState({loadedResults: this.state.loadedResults + 10});
  }

  showArchivedChanged(ev) {
    this.setState({showArchived: ev.target.checked ? 1 : 0});
  }

  render() {
    const allFiltered = this.state.accounts.filter(this.state.filter)
      .filter(x => x.archived === this.state.showArchived);
    const num = Math.min(allFiltered.length, this.state.loadedResults);
    const filtered = allFiltered.slice(0, num);
    return (
      <div className="container">
        <span>
          filter:
          <input
            className={this.state.filterValid ? "" : "invalid-input"}
            onChange={(e) => this.filterChanged(e)}
            type="text" value={this.state.filterText} />
        </span>
        <span className="results-text">
          showing {filtered.length} of {allFiltered.length} results
        </span>
        <span className="results-text">
          total: {this.state.accounts.length}
        </span>
        <span className="top-right">
        <input type="checkbox" checked={this.state.showArchived}
          onChange={(e) => this.showArchivedChanged(e)} /> show archived
        </span>
        <ol className="account-list">
          {filtered.map(x => this.renderAccount(x))}
        </ol>
        <button className="load-more" onClick={() => this.loadMore()}>
          load more
        </button>
      </div>
    );
  }

  componentDidMount() {
    this.fetchAccounts();
    this.timer = setInterval(() => this.fetchAccounts(), 5000);
  }

  componentWillUnmount() {
    clearInterval(this.timer);
    this.timer = null;
  }
}

ReactDOM.render(
  <Todokete />,
  document.getElementById('root')
);

